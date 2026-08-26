import pyshark


capture = pyshark.FileCapture(
    "data/pcaps/test_vpn.pcap"
)

for i, packet in enumerate(capture):

    print("\n" + "=" * 70)
    print(f"PACKET {i + 1}")
    print("=" * 70)

    if hasattr(packet, "isakmp"):

        print("\nIKE / ISAKMP FIELDS:\n")

        layer = packet.isakmp

        for field_name in layer.field_names:

            try:
                value = layer.get_field_value(field_name)

                print(
                    f"{field_name}: {value}"
                )

            except Exception:
                pass


capture.close()