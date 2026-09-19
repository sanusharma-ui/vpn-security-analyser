from core.signal import SecuritySignal
from parsers.context import endpoints


class IKEParser:

    # IKEv2 Encryption Transform IDs (RFC 7296)
    ENCRYPTION_ALGORITHMS = {
        1: "DES-IV64",
        2: "DES",
        3: "3DES",
        11: "NULL",
        12: "AES-CBC",
        13: "AES-CTR",
        18: "AES-GCM-8",
        19: "AES-GCM-12",
        20: "AES-GCM-16",
        28: "ChaCha20-Poly1305"
    }

    # IKEv1 Encryption Transform IDs (RFC 2409)
    IKEV1_ENCRYPTION_ALGORITHMS = {
        1: "DES-CBC",
        2: "IDEA-CBC",
        3: "Blowfish-CBC",
        4: "RC5-R16-B64-CBC",
        5: "3DES-CBC",
        6: "CAST-128-CBC",
        7: "AES-CBC"
    }

    # PRF Transform IDs (RFC 7296)
    PRF_ALGORITHMS = {
        1: "HMAC-MD5",
        2: "HMAC-SHA1",
        4: "AES128-XCBC",
        5: "HMAC-SHA2-256",
        6: "HMAC-SHA2-384",
        7: "HMAC-SHA2-512",
        8: "AES128-CMAC"
    }

    # IKEv1 Hash Transform IDs (RFC 2409)
    IKEV1_HASH_ALGORITHMS = {
        1: "HMAC-MD5",
        2: "HMAC-SHA1",
        3: "Tiger",
        4: "HMAC-SHA2-256",
        5: "HMAC-SHA2-384",
        6: "HMAC-SHA2-512"
    }

    # Integrity Transform IDs (RFC 7296)
    INTEGRITY_ALGORITHMS = {
        0: "NONE",
        1: "HMAC-MD5-96",
        2: "HMAC-SHA1-96",
        5: "AES-XCBC-96",
        12: "HMAC-SHA2-256-128",
        13: "HMAC-SHA2-384-192",
        14: "HMAC-SHA2-512-256"
    }

    # Diffie-Hellman Group IDs (RFC 7296 / RFC 2409)
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
        21: "521-bit ECP",
        31: "Curve25519"
    }

    # IKEv1 & IKEv2 Exchange Types
    EXCHANGE_TYPES = {
        1: "Base",
        2: "Main Mode",
        3: "Authentication Only",
        4: "Aggressive Mode",
        5: "Informational",
        32: "Quick Mode",
        33: "New Group Mode",
        34: "IKE_SA_INIT",
        35: "IKE_AUTH",
        36: "CREATE_CHILD_SA",
        37: "INFORMATIONAL"
    }

    # Common Notify Message Types (RFC 7296)
    NOTIFY_MESSAGES = {
        14: "NO_PROPOSAL_CHOSEN",
        17: "INVALID_KE_PAYLOAD",
        24: "AUTHENTICATION_FAILED",
        34: "SINGLE_PAIR_REQUIRED",
        16388: "NAT_DETECTION_SOURCE_IP",
        16389: "NAT_DETECTION_DESTINATION_IP",
        16390: "COOKIE",
        16400: "REDIRECT"
    }

    def parse(self, packet, packet_number=None):

        signals = []

        if not hasattr(packet, "isakmp"):
            return signals

        layer = packet.isakmp

        session_id = self._build_session_id(layer, packet)

        signals.append(
            self._signal(
                "ike_detected",
                True,
                packet_number,
                session_id,
                "protocol"
            )
        )

        major_version = self._get_int_field(layer, "mjver")

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

        # Initiator vs Responder Detection
        flag_i = self._get_field(layer, "flag_i")
        flag_r = self._get_field(layer, "flag_r")
        role = None
        if str(flag_i).lower() in ("true", "1"):
            role = "initiator"
        elif str(flag_i).lower() in ("false", "0"):
            role = "responder"

        if role:
            signals.append(
                self._signal(
                    "ike_role",
                    role,
                    packet_number,
                    session_id,
                    "session"
                )
            )

        # Exchange Type & Aggressive Mode Check
        exchange_type = self._get_int_field(layer, "exchangetype")

        if exchange_type is not None:
            exchange_name = self.EXCHANGE_TYPES.get(
                exchange_type,
                f"TYPE-{exchange_type}"
            )
            signals.append(
                self._signal(
                    "ike_exchange",
                    exchange_name,
                    packet_number,
                    session_id,
                    "protocol"
                )
            )

            # Flag IKEv1 Aggressive Mode specifically
            if major_version == 1 and exchange_type == 4:
                signals.append(
                    self._signal(
                        "is_aggressive_mode",
                        True,
                        packet_number,
                        session_id,
                        "vulnerability"
                    )
                )

        # Encryption Algorithm Extraction (IKEv2 & IKEv1 fallback)
        encryption_id = self._get_int_field(layer, "tf_id_encr")
        enc_name = None

        if encryption_id is not None:
            enc_name = self.ENCRYPTION_ALGORITHMS.get(
                encryption_id,
                f"UNKNOWN-{encryption_id}"
            )
            signals.append(
                self._signal("encryption_id", encryption_id, packet_number, session_id, "crypto")
            )
        else:
            # Check IKEv1 transform attribute
            v1_enc = self._get_int_field(layer, "trans_attr_enc")
            if v1_enc is None:
                v1_enc = self._get_int_field(layer, "isakmp_tf_attr_enc_alg")
            if v1_enc is not None:
                enc_name = self.IKEV1_ENCRYPTION_ALGORITHMS.get(
                    v1_enc,
                    f"UNKNOWN-V1-{v1_enc}"
                )
                signals.append(
                    self._signal("encryption_id", v1_enc, packet_number, session_id, "crypto")
                )

        if enc_name:
            signals.append(
                self._signal("encryption", enc_name, packet_number, session_id, "crypto")
            )

        # Key Length Extraction
        key_length = self._get_int_field(layer, "ike2_attr_key_length")
        if key_length is None:
            key_length = self._get_int_field(layer, "trans_attr_key_length")

        if key_length is not None:
            signals.append(
                self._signal("key_length", key_length, packet_number, session_id, "crypto")
            )

        # PRF / Hash Extraction
        prf_id = self._get_int_field(layer, "tf_id_prf")
        prf_name = None

        if prf_id is not None:
            prf_name = self.PRF_ALGORITHMS.get(prf_id, f"UNKNOWN-{prf_id}")
            signals.append(
                self._signal("prf_id", prf_id, packet_number, session_id, "crypto")
            )
        else:
            v1_hash = self._get_int_field(layer, "trans_attr_hash")
            if v1_hash is not None:
                prf_name = self.IKEV1_HASH_ALGORITHMS.get(v1_hash, f"UNKNOWN-HASH-{v1_hash}")
                signals.append(
                    self._signal("prf_id", v1_hash, packet_number, session_id, "crypto")
                )

        if prf_name:
            signals.append(
                self._signal("prf", prf_name, packet_number, session_id, "crypto")
            )

        # Integrity Algorithm Extraction
        integrity_id = self._get_int_field(layer, "tf_id_integ")

        if integrity_id is not None:
            signals.append(
                self._signal("integrity_id", integrity_id, packet_number, session_id, "crypto")
            )
            signals.append(
                self._signal(
                    "integrity",
                    self.INTEGRITY_ALGORITHMS.get(integrity_id, f"UNKNOWN-{integrity_id}"),
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

        # Diffie-Hellman Group Extraction
        dh_group = self._get_int_field(layer, "tf_id_dh")
        if dh_group is None:
            dh_group = self._get_int_field(layer, "key_exchange_dh_group")
        if dh_group is None:
            dh_group = self._get_int_field(layer, "trans_attr_group_desc")

        if dh_group is not None:
            signals.append(
                self._signal("dh_group", dh_group, packet_number, session_id, "crypto")
            )
            signals.append(
                self._signal(
                    "dh_group_name",
                    self.DH_GROUPS.get(dh_group, f"GROUP-{dh_group}"),
                    packet_number,
                    session_id,
                    "crypto"
                )
            )

        # Nonce Length & Entropy Extraction
        nonce_val = self._get_field(layer, "nonce")
        if nonce_val:
            try:
                hex_str = str(nonce_val).replace(":", "").replace(" ", "")
                nonce_bytes = len(bytes.fromhex(hex_str))
                signals.append(
                    self._signal(
                        "nonce_length",
                        nonce_bytes,
                        packet_number,
                        session_id,
                        "crypto"
                    )
                )
                if nonce_bytes < 16:
                    signals.append(
                        self._signal(
                            "short_nonce",
                            True,
                            packet_number,
                            session_id,
                            "vulnerability"
                        )
                    )
            except Exception:
                pass

        # Notify Messages Extraction (e.g. NO_PROPOSAL_CHOSEN)
        notify_type = self._get_int_field(layer, "notify_msgtype")
        if notify_type is not None:
            notify_name = self.NOTIFY_MESSAGES.get(notify_type, f"TYPE-{notify_type}")
            signals.append(
                self._signal(
                    "ike_notify",
                    notify_name,
                    packet_number,
                    session_id,
                    "protocol"
                )
            )
            if notify_type == 14:
                signals.append(
                    self._signal(
                        "no_proposal_chosen",
                        True,
                        packet_number,
                        session_id,
                        "vulnerability"
                    )
                )

        # Read every repeated transform, without inventing cross-proposal pairings.
        fields = {
            "encryption": ("tf_id_encr", self.ENCRYPTION_ALGORITHMS),
            "prf": ("tf_id_prf", self.PRF_ALGORITHMS),
            "integrity": ("tf_id_integ", self.INTEGRITY_ALGORITHMS),
            "dh_group": ("tf_id_dh", None),
            "key_length": ("ike2_attr_key_length", None),
        }
        if major_version == 1:
            fields = {
                "encryption": ("trans_attr_enc", self.IKEV1_ENCRYPTION_ALGORITHMS),
                "prf": ("trans_attr_hash", self.IKEV1_HASH_ALGORITHMS),
                "dh_group": ("trans_attr_group_desc", None),
                "key_length": ("trans_attr_key_length", None),
            }
        for name, (field, mapping) in fields.items():
            for raw in self._get_fields(layer, field):
                try:
                    number = int(str(raw), 0)
                except (ValueError, TypeError):
                    continue
                value = mapping.get(number, f"UNKNOWN-{number}") if mapping else number
                if not any(s.name == name and s.value == value for s in signals):
                    signals.append(self._signal(name, value, packet_number, session_id, "crypto"))
        scope = "observed"
        if major_version == 2 and exchange_type == 34:
            if str(flag_r).lower() in ("true", "1"):
                scope = "selected"
            elif str(flag_r).lower() in ("false", "0"):
                scope = "offered"
        for signal in signals:
            if signal.category == "crypto" and signal.name not in ("nonce_length",):
                signal.scope = scope
        return signals

    def _get_fields(self, layer, name):
        try:
            container = layer.get_field(name)
            values = getattr(container, "all_fields", None)
            if isinstance(values, (list, tuple)) and values:
                return [getattr(v, "show", str(v)) for v in values]
        except (AttributeError, KeyError):
            pass
        value = self._get_field(layer, name)
        return value if isinstance(value, list) else [value]

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

    def _build_session_id(self, layer, packet):
        initiator = self._get_field(layer, "ispi")
        if not initiator:
            return None
        src, dst = endpoints(packet)
        peers = "|".join(sorted((src, dst)))
        responder = self._get_field(layer, "rspi") or "0"
        compact = str(responder).replace(":", "").removeprefix("0x")
        if compact and set(compact) == {"0"}:
            responder = "0"
        return f"ike:{peers}:{initiator}/{responder}"

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