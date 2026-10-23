"""L1 — capture engine.

Three interchangeable sources, one interface, so nothing downstream knows or
cares where packets came from:

  LiveCapture      Scapy AsyncSniffer on a daemon thread (needs root/BPF access)
  PcapSource       rdpcap replay, optionally paced at the original timing
  SimulatedSource  synthetic wall-clock traffic — the zero-privilege demo path

All three push into a bounded ring buffer with a drop-oldest policy and an
explicit drop counter, which is what decouples capture rate from UI refresh
rate (novelty N4) and gives the evaluation phase a real "packets dropped per
second" number instead of a guess.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from . import config
from .parser import SCAPY_AVAILABLE, parse_packet


def list_interfaces() -> list[str]:
    """Interface names available for live capture (empty if Scapy is absent)."""
    if not SCAPY_AVAILABLE:
        return []
    try:
        from scapy.arch import get_if_list
        return sorted(get_if_list())
    except Exception:
        return []


class RingBuffer:
    """Bounded FIFO. When full, the oldest record is dropped and counted."""

    def __init__(self, size: int = config.RING_BUFFER_SIZE):
        self.size = size
        self._dq: deque = deque()
        self._lock = threading.Lock()
        self.dropped = 0
        self.accepted = 0

    def put(self, rec: dict) -> None:
        with self._lock:
            if len(self._dq) >= self.size:
                self._dq.popleft()
                self.dropped += 1
            self._dq.append(rec)
            self.accepted += 1

    def drain(self, limit: int | None = None) -> list[dict]:
        with self._lock:
            if limit is None or limit >= len(self._dq):
                out, self._dq = list(self._dq), deque()
            else:
                out = [self._dq.popleft() for _ in range(limit)]
        return out

    def __len__(self) -> int:
        return len(self._dq)


class PacketSource:
    """Common contract for every capture source."""

    name = "source"

    def __init__(self):
        self.buffer = RingBuffer()
        self.started_at: float | None = None
        self.running = False
        self.error: str | None = None

    def start(self) -> None:
        self.started_at = time.time()
        self.running = True

    def stop(self) -> None:
        self.running = False

    def poll(self, limit: int | None = None) -> list[dict]:
        return self.buffer.drain(limit)

    def stats(self) -> dict:
        elapsed = (time.time() - self.started_at) if self.started_at else 0.0
        return {
            "source": self.name,
            "running": self.running,
            "elapsed": elapsed,
            "buffered": len(self.buffer),
            "accepted": self.buffer.accepted,
            "dropped": self.buffer.dropped,
            "drop_rate": (self.buffer.dropped / self.buffer.accepted
                          if self.buffer.accepted else 0.0),
            "pps": (self.buffer.accepted / elapsed) if elapsed > 0.5 else 0.0,
            "error": self.error,
        }


class LiveCapture(PacketSource):
    """Scapy AsyncSniffer on a daemon thread."""

    name = "live"

    def __init__(self, iface: str | None = None, bpf: str = config.DEFAULT_BPF):
        super().__init__()
        self.iface = iface
        self.bpf = (bpf or "").strip()
        self._sniffer = None

    def _on_packet(self, pkt) -> None:
        rec = parse_packet(pkt, ts=float(getattr(pkt, "time", time.time())))
        if rec is not None:
            self.buffer.put(rec)

    def start(self) -> None:
        if not SCAPY_AVAILABLE:
            self.error = "Scapy is not available in this environment."
            return
        from scapy.sendrecv import AsyncSniffer
        kwargs = {"prn": self._on_packet, "store": False}
        if self.iface:
            kwargs["iface"] = self.iface
        if self.bpf:
            kwargs["filter"] = self.bpf
        try:
            self._sniffer = AsyncSniffer(**kwargs)
            self._sniffer.start()
            super().start()
        except Exception as exc:                      # permissions, bad BPF, no iface
            self.error = (f"{type(exc).__name__}: {exc}  —  live capture needs "
                          f"raw-socket privileges (run with sudo, or use "
                          f"Simulated / PCAP mode).")

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        super().stop()


class PcapSource(PacketSource):
    """Replay a capture file, either as fast as possible or at original pace."""

    name = "pcap"

    def __init__(self, path: str, realtime: bool = False, speed: float = 1.0):
        super().__init__()
        self.path = str(path)
        self.realtime = realtime
        self.speed = max(0.01, speed)
        self._thread: threading.Thread | None = None
        self.total = 0

    def _run(self) -> None:
        try:
            from scapy.utils import rdpcap
            packets = rdpcap(self.path)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self.running = False
            return

        self.total = len(packets)
        first = float(getattr(packets[0], "time", 0.0)) if packets else 0.0
        wall0 = time.time()
        for pkt in packets:
            if not self.running:
                break
            pts = float(getattr(pkt, "time", 0.0))
            if self.realtime:
                target = wall0 + (pts - first) / self.speed
                delay = target - time.time()
                if delay > 0:
                    time.sleep(min(delay, 2.0))
                rec = parse_packet(pkt, ts=time.time())
            else:
                rec = parse_packet(pkt, ts=pts)
            if rec is not None:
                self.buffer.put(rec)
        self.running = False

    def start(self) -> None:
        super().start()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="netlens-pcap")
        self._thread.start()

    def stats(self) -> dict:
        s = super().stats()
        s["pcap_total"] = self.total
        return s


class SimulatedSource(PacketSource):
    """Synthetic wall-clock traffic — full pipeline, no privileges required."""

    name = "simulated"

    def __init__(self, seed: int | None = None, benign_rate: float = 2.5,
                 auto_attacks: bool = True):
        super().__init__()
        from .synth import TrafficSimulator
        self.sim = TrafficSimulator(seed=seed, benign_rate=benign_rate,
                                    auto_attacks=auto_attacks)

    def poll(self, limit: int | None = None) -> list[dict]:
        for rec in self.sim.poll():
            self.buffer.put(rec)
        return self.buffer.drain(limit)

    def inject(self, name: str) -> str:
        return self.sim.inject(name)

    def stats(self) -> dict:
        s = super().stats()
        s.update(self.sim.stats())
        return s


def make_source(mode: str, **kwargs) -> PacketSource:
    """Factory used by the dashboard sidebar."""
    mode = (mode or "").lower()
    if mode.startswith("live"):
        return LiveCapture(iface=kwargs.get("iface"), bpf=kwargs.get("bpf", ""))
    if mode.startswith("pcap"):
        return PcapSource(kwargs["path"], realtime=kwargs.get("realtime", True),
                          speed=kwargs.get("speed", 1.0))
    return SimulatedSource(seed=kwargs.get("seed"),
                           benign_rate=kwargs.get("benign_rate", 2.5),
                           auto_attacks=kwargs.get("auto_attacks", True))
