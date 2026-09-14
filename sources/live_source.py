import pyshark
from sources.base_source import BaseSource


class LiveSource(BaseSource):
    """
    Live network interface packet capture source for real-time VPN inspection.
    Uses kernel-level BPF filtering (Berkeley Packet Filter) to isolate VPN traffic
    (IKE UDP 500, NAT-T UDP 4500, ESP, AH) without overwhelming system resources.
    """

    DEFAULT_BPF_FILTER = "udp port 500 or udp port 4500 or esp or ah"

    def __init__(
        self,
        interface=None,
        capture_filter=None,
        display_filter=None,
        packet_count=None,
        timeout=None
    ):
        self.interface = interface
        self.bpf_filter = capture_filter if capture_filter is not None else self.DEFAULT_BPF_FILTER
        self.display_filter = display_filter
        self.packet_count = packet_count
        self.timeout = timeout
        self.capture = None

    @classmethod
    def list_interfaces(cls):
        """
        Enumerates all available network interfaces on the host machine.
        Returns a list of dictionaries with interface index and name.
        """
        interfaces = []
        try:
            from pyshark.tshark.tshark import get_all_tshark_interfaces_names
            names = get_all_tshark_interfaces_names()
            for idx, name in enumerate(names):
                interfaces.append({
                    "index": idx + 1,
                    "name": name
                })
        except Exception:
            try:
                import subprocess
                output = subprocess.check_output(
                    ["tshark", "-D"],
                    text=True,
                    stderr=subprocess.DEVNULL
                )
                for line in output.strip().splitlines():
                    if line:
                        parts = line.split(". ", 1)
                        if len(parts) == 2:
                            interfaces.append({
                                "index": int(parts[0]),
                                "name": parts[1].strip()
                            })
                        else:
                            interfaces.append({
                                "index": len(interfaces) + 1,
                                "name": line.strip()
                            })
            except Exception:
                pass
        return interfaces

    def read(self):
        """
        Initializes live capture on the specified or default interface
        and yields packets in a generator stream.
        """
        capture_kwargs = {
            "bpf_filter": self.bpf_filter,
            "display_filter": self.display_filter,
        }
        if self.interface:
            capture_kwargs["interface"] = self.interface

        try:
            self.capture = pyshark.LiveCapture(**capture_kwargs)
        except Exception as err:
            raise RuntimeError(
                f"Failed to start LiveCapture on interface '{self.interface}': {err}. "
                "Ensure Wireshark/Npcap is installed and running with appropriate permissions."
            ) from err

        def packet_stream():
            count = 0
            try:
                for packet in self.capture.sniff_continuously(packet_count=self.packet_count):
                    yield packet
                    count += 1
                    if self.packet_count and count >= self.packet_count:
                        break
            except Exception:
                pass
            finally:
                self.close()

        return packet_stream()

    def close(self):
        """
        Stops live capture and terminates tshark subprocess safely.
        """
        if self.capture:
            try:
                self.capture.close()
            except Exception:
                pass
            self.capture = None