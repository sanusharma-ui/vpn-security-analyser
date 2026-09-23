"""Reconstruct bounded IKEv2 proposals using PDML byte ranges, never array order."""

MAX_PROPOSALS = 16
MAX_TRANSFORMS = 32
MAX_FIELDS = 2048


def number(value):
    try:
        text = str(value)
        return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    except (ValueError, TypeError):
        return None


def proposal_details(layer, mappings):
    fields = {}
    limited = False
    for name in ("typepayload", "payloadlength", "prop_number", "prop_protoid",
                 "prop_transforms", "spisize", "tf_type", "tf_id_encr", "tf_id_prf",
                 "tf_id_integ", "tf_id_dh", "tf_id_esn", "ike2_attr_key_length"):
        try:
            values = getattr(layer.get_field(name), "all_fields", None)
        except (AttributeError, KeyError):
            values = None
        if not isinstance(values, (list, tuple)):
            values = []
        limited |= len(values) > MAX_FIELDS
        fields[name] = [
            (number(getattr(f, "pos", None)), number(getattr(f, "size", None)),
             number(getattr(f, "show", None))) for f in values[:MAX_FIELDS]
        ]

    result = {"status": "UNAVAILABLE", "association": "packet_byte_ranges",
              "proposals": [], "reasons": [], "truncated": limited}
    payloads = fields["typepayload"]
    proposals = [(p, n) for p, n, kind in payloads if kind == 2]
    if not proposals:
        if limited or any(kind == 33 for _, _, kind in payloads):
            result["status"] = "PARTIAL"
        result["reasons"] = ["proposal_byte_ranges_unavailable"]
        return result

    def at(name, position):
        values = [v for p, n, v in fields[name] if p == position]
        return values[0] if len(values) == 1 else None

    def contained(start, size, parent, parent_size, minimum):
        return (isinstance(start, int) and isinstance(size, int) and size >= minimum
                and isinstance(parent, int) and isinstance(parent_size, int)
                and parent <= start and start + size <= parent + parent_size)

    if len(proposals) > MAX_PROPOSALS:
        result["truncated"] = True
    associated = {name: 0 for name in ("tf_id_encr", "tf_id_prf", "tf_id_integ",
                                      "tf_id_dh", "tf_id_esn", "ike2_attr_key_length")}
    previous_end = -1
    for start, size in proposals[:MAX_PROPOSALS]:
        parents = [(p, n) for p, n, kind in payloads if kind == 33
                   and isinstance(p, int) and isinstance(n, int)
                   and contained(start, size, p + 4, n - 4, 8)
                   and at("payloadlength", p + 2) == n]
        if (len(parents) != 1 or start < previous_end
                or at("payloadlength", start + 2) != size):
            result["reasons"].append("invalid_proposal_boundary")
            continue
        previous_end = start + size
        proposal = {"number": at("prop_number", start + 4),
                    "protocol_id": at("prop_protoid", start + 5),
                    "declared_transforms": at("prop_transforms", start + 7),
                    "byte_offset": start, "byte_length": size, "transforms": []}
        if proposal["number"] is None or not 1 <= proposal["number"] <= 255:
            result["reasons"].append("invalid_proposal_number")
        if proposal["protocol_id"] != 1 or at("spisize", start + 6) != 0:
            result["reasons"].append("invalid_initial_ike_proposal_protocol_or_spi")
        transforms = [(p, n) for p, n, kind in payloads if kind == 3
                      and contained(p, n, start + 8, size - 8, 8)]
        if len(transforms) != proposal["declared_transforms"]:
            result["reasons"].append("transform_count_mismatch")
        if len(transforms) > MAX_TRANSFORMS:
            result["truncated"] = True
        transform_end = start + 8
        for pos, length in transforms[:MAX_TRANSFORMS]:
            if pos != transform_end or at("payloadlength", pos + 2) != length:
                result["reasons"].append("invalid_transform_boundary")
                continue
            transform_end = pos + length
            kind = at("tf_type", pos + 4)
            field, mapping = mappings.get(kind, (None, {}))
            identifier = at(field, pos + 6) if field else None
            if field and identifier is not None:
                associated[field] += 1
            if kind is None or identifier is None:
                result["reasons"].append("unsupported_or_missing_transform")
            keys = [v for p, n, v in fields["ike2_attr_key_length"]
                    if contained(p, n, pos + 8, length - 8, 1)]
            associated["ike2_attr_key_length"] += len(keys)
            if any(k is None for k in keys) or len(keys) > 1 or (keys and kind != 1):
                result["reasons"].append("ambiguous_key_length")
            proposal["transforms"].append({
                "type": kind, "id": identifier,
                "name": mapping.get(identifier, f"UNKNOWN-{identifier}"),
                "key_length": keys[0] if kind == 1 and len(keys) == 1 else None,
                "byte_offset": pos, "byte_length": length,
            })
        if transform_end != start + size:
            result["reasons"].append("unaccounted_proposal_bytes")
        result["proposals"].append(proposal)
    if any(count != len(fields[name]) for name, count in associated.items()):
        result["reasons"].append("unassociated_transform_or_attribute")
    sas = [(p, n) for p, n, kind in payloads if kind == 33]
    if len(sas) != 1:
        result["reasons"].append("ambiguous_sa_payloads")
    for start, size in sas:
        if not isinstance(start, int) or not isinstance(size, int):
            result["reasons"].append("invalid_sa_boundary")
            continue
        cursor = start + 4
        for proposal in result["proposals"]:
            if contained(proposal["byte_offset"], proposal["byte_length"], start, size, 8):
                if proposal["byte_offset"] != cursor:
                    result["reasons"].append("unaccounted_sa_bytes")
                cursor = proposal["byte_offset"] + proposal["byte_length"]
        if cursor != start + size:
            result["reasons"].append("unaccounted_sa_bytes")
    result["reasons"] = list(dict.fromkeys(result["reasons"]))
    result["status"] = "PARTIAL" if result["reasons"] or result["truncated"] else "COMPLETE"
    return result
