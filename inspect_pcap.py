from core.signal import SecuritySignal


class IKEParser:

    ENCRYPTION_ALGORITHMS = {
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

    DH_GROUPS = {
        14: "2048-bit MODP",
        15: "3072-bit MODP",
        16: "4096-bit MODP",
        17: "6144-bit MODP",
        18: "8192-bit MODP",
        19: "256-bit ECP",
        20: "384-bit ECP",
        21: "521-bit ECP"
    }

    def parse(self, packet):

        signals = []

        if not hasattr(packet, "isakmp"):
            return signals

        layer = packet.isakmp

        signals.append(
            SecuritySignal(
                name="ike_detected",
                value=True,
                source="pcap"
            )
        )

        major_version = self._get_field(
            layer,
            ["mjver", "majorversion", "major_version"]
        )

        if major_version:
            try:
                major = int(str(major_version), 0)

                signals.append(
                    SecuritySignal(
                        name="ike_version",
                        value=f"IKEv{major}",
                        source="pcap"
                    )
                )

            except ValueError:
                pass

        encryption_id = self._get_int_field(
            layer,
            "tf_id_encr"
        )

        if encryption_id is not None:

            algorithm = self.ENCRYPTION_ALGORITHMS.get(
                encryption_id,
                f"UNKNOWN-{encryption_id}"
            )

            signals.append(
                SecuritySignal(
                    name="encryption",
                    value=algorithm,
                    source="pcap"
                )
            )

        key_length = self._get_int_field(
            layer,
            "ike2_attr_key_length"
        )

        if key_length is not None:

            signals.append(
                SecuritySignal(
                    name="key_length",
                    value=key_length,
                    source="pcap"
                )
            )

        prf_id = self._get_int_field(
            layer,
            "tf_id_prf"
        )

        if prf_id is not None:

            prf = self.PRF_ALGORITHMS.get(
                prf_id,
                f"UNKNOWN-{prf_id}"
            )

            signals.append(
                SecuritySignal(
                    name="prf",
                    value=prf,
                    source="pcap"
                )
            )

        dh_id = self._get_int_field(
            layer,
            "tf_id_dh"
        )

        if dh_id is None:
            dh_id = self._get_int_field(
                layer,
                "key_exchange_dh_group"
            )

        if dh_id is not None:

            dh_name = self.DH_GROUPS.get(
                dh_id,
                f"GROUP-{dh_id}"
            )

            signals.append(
                SecuritySignal(
                    name="dh_group",
                    value=dh_id,
                    source="pcap"
                )
            )

            signals.append(
                SecuritySignal(
                    name="dh_group_name",
                    value=dh_name,
                    source="pcap"
                )
            )

        exchange_type = self._get_int_field(
            layer,
            "exchangetype"
        )

        if exchange_type is not None:

            exchange_names = {
                34: "IKE_SA_INIT",
                35: "IKE_AUTH",
                36: "CREATE_CHILD_SA",
                37: "INFORMATIONAL"
            }

            signals.append(
                SecuritySignal(
                    name="ike_exchange",
                    value=exchange_names.get(
                        exchange_type,
                        f"TYPE-{exchange_type}"
                    ),
                    source="pcap"
                )
            )

        return signals

    def _get_field(self, layer, names):

        for name in names:

            try:
                value = layer.get_field_value(name)

                if value is not None:
                    return value

            except Exception:
                continue

        return None

    def _get_int_field(self, layer, name):

        try:

            value = layer.get_field_value(name)

            if value is None:
                return None

            return int(str(value), 0)

        except (ValueError, TypeError):
            return None

        except Exception:
            return None