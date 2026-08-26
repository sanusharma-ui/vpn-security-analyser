from parsers.ike_parser import IKEParser
from parsers.ipsec_parser import IPsecParser


class PacketParser:

    def __init__(self):

        self.ike_parser = IKEParser()
        self.ipsec_parser = IPsecParser()

    def parse(
        self,
        packet,
        packet_number=None
    ):

        signals = []

        signals.extend(
            self.ike_parser.parse(
                packet,
                packet_number
            )
        )

        signals.extend(
            self.ipsec_parser.parse(
                packet,
                packet_number
            )
        )

        return signals