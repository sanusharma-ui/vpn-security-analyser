import asyncio
import queue
import threading
import pyshark
from sources.base_source import BaseSource


class LiveSource(BaseSource):
    DEFAULT_BPF_FILTER = "udp port 500 or udp port 4500 or esp or ah"

    def __init__(self, interface=None, capture_filter=None, display_filter=None,
                 packet_count=None, timeout=None, queue_size=1024):
        if packet_count is not None and packet_count <= 0:
            raise ValueError("Packet count must be positive")
        if timeout is not None and timeout <= 0:
            raise ValueError("Timeout must be positive")
        if queue_size <= 0:
            raise ValueError("Queue size must be positive")
        self.interface, self.display_filter = interface, display_filter
        self.bpf_filter = capture_filter if capture_filter is not None else self.DEFAULT_BPF_FILTER
        self.packet_count, self.timeout = packet_count, timeout
        self.capture = self._thread = self._loop = self._task = None
        self._queue = queue.Queue(maxsize=queue_size)
        self._done = threading.Event()
        self._stop = threading.Event()
        self.error = None
        self.status = "ready"
        self.queue_drops = 0

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
            except Exception as err:
                raise RuntimeError("Could not enumerate interfaces; check TShark/Npcap installation and permissions.") from err
        return interfaces

    def _worker(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        async def run():
            self.capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter,
                display_filter=self.display_filter, eventloop=self._loop)
            def accept(packet):
                try:
                    self._queue.put_nowait(packet)
                except queue.Full:
                    self.queue_drops += 1
            try:
                await asyncio.wait_for(self.capture.packets_from_tshark(accept,
                    packet_count=self.packet_count), timeout=self.timeout)
                self.status = "complete"
            except asyncio.TimeoutError:
                self.status = "timeout"
            finally:
                await self.capture.close_async()
        try:
            self._task = self._loop.create_task(run())
            if self._stop.is_set():
                self._task.cancel()
            self._loop.run_until_complete(self._task)
        except asyncio.CancelledError:
            self.status = "stopped"
        except Exception as err:
            self.error = err
            self.status = "error"
        finally:
            self._loop.close()
            self._done.set()

    def read(self):
        if self._thread is not None:
            raise RuntimeError("Create a new LiveSource for each capture")
        self.status = "capturing"
        self._thread = threading.Thread(target=self._worker, daemon=True, name="vpn-capture")
        self._thread.start()
        def stream():
            try:
                while not self._done.is_set() or not self._queue.empty():
                    try:
                        yield self._queue.get(timeout=0.5)
                    except queue.Empty:
                        yield None  # heartbeat: allows idle reports and Ctrl+C
                if self.error:
                    raise RuntimeError("Live capture failed; check interface, TShark/Npcap and capture permissions.") from self.error
            finally:
                self.close()
        return stream()

    def close(self):
        self._stop.set()
        if self._loop and self._task and not self._done.is_set():
            try:
                self._loop.call_soon_threadsafe(self._task.cancel)
            except RuntimeError:
                pass  # worker finished between the state check and cancellation
        if self._thread:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                raise RuntimeError("Capture worker did not stop within five seconds")
