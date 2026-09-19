"""Capture context only; endpoint metadata never goes to the AI provider."""


def endpoints(packet):
    for name in ("ip", "ipv6"):
        layer = getattr(packet, name, None)
        if layer is not None:
            src, dst = getattr(layer, "src", None), getattr(layer, "dst", None)
            if isinstance(src, str) and isinstance(dst, str):
                return src, dst
    return "unknown", "unknown"


def timestamp(packet):
    value = getattr(packet, "sniff_timestamp", None)
    return str(value) if isinstance(value, (str, int, float)) else None
