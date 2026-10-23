"""L2b — bidirectional flow aggregation and feature extraction.

Packets are keyed on the canonical 5-tuple so that A->B and B->A land in the
same flow.  Statistics are kept as running accumulators (count / sum / sum of
squares / min / max) rather than packet lists, so memory per flow is constant
regardless of how long the flow lives — that is what keeps the flow-table
footprint measurable in the evaluation phase.

FEATURE_NAMES is the single source of truth for the model's input layout: the
live dashboard and the offline trainer both build vectors from it, so a feature
can never silently mean two different things.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from . import config

FEATURE_NAMES = [
    # shape of the conversation
    "duration", "total_packets", "fwd_packets", "bwd_packets",
    "total_bytes", "fwd_bytes", "bwd_bytes",
    # packet size distribution
    "mean_pkt_len", "std_pkt_len", "min_pkt_len", "max_pkt_len",
    "fwd_mean_len", "bwd_mean_len",
    # rates
    "packets_per_sec", "bytes_per_sec",
    # inter-arrival timing
    "mean_iat", "std_iat", "min_iat", "max_iat",
    # directionality
    "down_up_bytes_ratio", "fwd_bwd_pkt_ratio", "bwd_fraction",
    # TCP control-plane behaviour
    "syn_count", "synack_count", "ack_count", "fin_count", "rst_count",
    "psh_count", "syn_ratio", "rst_ratio", "handshake_complete",
    # header / protocol context
    "mean_ttl", "is_tcp", "is_udp", "is_icmp",
    "dst_port_wellknown", "dns_entropy_max",
]


def _std(n: int, total: float, sq: float) -> float:
    if n < 2:
        return 0.0
    var = (sq / n) - (total / n) ** 2
    return math.sqrt(var) if var > 0 else 0.0


def _safe_ratio(a: float, b: float) -> float:
    return a / b if b else float(a)


@dataclass
class RunningStat:
    """count / sum / sum-of-squares / min / max in constant space."""

    n: int = 0
    total: float = 0.0
    sq: float = 0.0
    lo: float = float("inf")
    hi: float = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        self.total += x
        self.sq += x * x
        self.lo = min(self.lo, x)
        self.hi = max(self.hi, x)

    @property
    def mean(self) -> float:
        return self.total / self.n if self.n else 0.0

    @property
    def std(self) -> float:
        return _std(self.n, self.total, self.sq)

    @property
    def min(self) -> float:
        return 0.0 if self.lo == float("inf") else self.lo

    @property
    def max(self) -> float:
        return self.hi


@dataclass
class Flow:
    """One bidirectional conversation."""

    key: tuple
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    proto: str
    start_ts: float
    last_ts: float = 0.0

    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    lens: RunningStat = field(default_factory=RunningStat)
    fwd_lens: RunningStat = field(default_factory=RunningStat)
    bwd_lens: RunningStat = field(default_factory=RunningStat)
    iats: RunningStat = field(default_factory=RunningStat)
    ttls: RunningStat = field(default_factory=RunningStat)

    syn: int = 0
    synack: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    urg: int = 0

    dns_entropy_max: float = 0.0
    dns_qnames: list = field(default_factory=list)
    service: str = "OTHER"
    label: str | None = None            # ground truth, synthetic data only
    ladder: list = field(default_factory=list)
    closed_reason: str | None = None

    # ------------------------------------------------------------ ingest
    def update(self, rec: dict, forward: bool) -> None:
        if self.last_ts:
            self.iats.add(max(0.0, rec["ts"] - self.last_ts))
        self.last_ts = rec["ts"]

        size = rec["length"]
        self.lens.add(size)
        if forward:
            self.fwd_packets += 1
            self.fwd_bytes += size
            self.fwd_lens.add(size)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += size
            self.bwd_lens.add(size)

        if rec.get("ttl") is not None:
            self.ttls.add(rec["ttl"])

        flags = rec.get("flags") or ""
        if flags:
            if "S" in flags and "A" in flags:
                self.synack += 1
            elif "S" in flags:
                self.syn += 1
            if "A" in flags:
                self.ack += 1
            if "F" in flags:
                self.fin += 1
            if "R" in flags:
                self.rst += 1
            if "P" in flags:
                self.psh += 1
            if "U" in flags:
                self.urg += 1

        if rec.get("dns_qname"):
            self.dns_entropy_max = max(self.dns_entropy_max, rec.get("dns_entropy", 0.0))
            if len(self.dns_qnames) < 20:
                self.dns_qnames.append(rec["dns_qname"])

        if rec.get("service") and self.service == "OTHER":
            self.service = rec["service"]
        if rec.get("label") and self.label is None:
            self.label = rec["label"]

        if len(self.ladder) < config.MAX_LADDER_PACKETS:
            self.ladder.append({
                "ts": rec["ts"],
                "forward": forward,
                "flags": flags,
                "length": size,
                "payload_len": rec.get("payload_len") or 0,
                "proto": rec["proto"],
                "seq": rec.get("seq"),
                "ack": rec.get("ack"),
                "dns_qname": rec.get("dns_qname"),
                "icmp_type": rec.get("icmp_type"),
            })

    # ------------------------------------------------------------ derived
    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.start_ts)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def terminated(self) -> bool:
        """Did this conversation actually end, rather than merely pause?

        Both sides sent FIN (graceful close) or somebody sent RST (abort).
        A TCP flow that is simply idle has not ended — an interactive SSH
        session is idle between keystrokes.
        """
        return self.fin >= 2 or self.rst >= 1

    @property
    def handshake_complete(self) -> int:
        """1 only if SYN, SYN-ACK and a following ACK were all observed."""
        return int(self.syn >= 1 and self.synack >= 1 and self.ack >= 2)

    def features(self) -> dict:
        """The 37-feature vector consumed by L3."""
        dur = self.duration
        eff = dur if dur > 0 else 1e-3
        return {
            "duration": round(dur, 6),
            "total_packets": self.total_packets,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "total_bytes": self.total_bytes,
            "fwd_bytes": self.fwd_bytes,
            "bwd_bytes": self.bwd_bytes,
            "mean_pkt_len": self.lens.mean,
            "std_pkt_len": self.lens.std,
            "min_pkt_len": self.lens.min,
            "max_pkt_len": self.lens.max,
            "fwd_mean_len": self.fwd_lens.mean,
            "bwd_mean_len": self.bwd_lens.mean,
            "packets_per_sec": self.total_packets / eff,
            "bytes_per_sec": self.total_bytes / eff,
            "mean_iat": self.iats.mean,
            "std_iat": self.iats.std,
            "min_iat": self.iats.min,
            "max_iat": self.iats.max,
            "down_up_bytes_ratio": _safe_ratio(self.bwd_bytes, self.fwd_bytes),
            "fwd_bwd_pkt_ratio": _safe_ratio(self.fwd_packets, self.bwd_packets),
            "bwd_fraction": _safe_ratio(self.bwd_packets, self.total_packets),
            "syn_count": self.syn,
            "synack_count": self.synack,
            "ack_count": self.ack,
            "fin_count": self.fin,
            "rst_count": self.rst,
            "psh_count": self.psh,
            "syn_ratio": _safe_ratio(self.syn, self.total_packets),
            "rst_ratio": _safe_ratio(self.rst, self.total_packets),
            "handshake_complete": self.handshake_complete,
            "mean_ttl": self.ttls.mean,
            "is_tcp": int(self.proto == "TCP"),
            "is_udp": int(self.proto == "UDP"),
            "is_icmp": int(self.proto == "ICMP"),
            "dst_port_wellknown": int((self.dst_port or 65535) < 1024),
            "dns_entropy_max": self.dns_entropy_max,
        }

    def vector(self) -> list:
        f = self.features()
        return [f[name] for name in FEATURE_NAMES]

    def summary(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "src": f"{self.src_ip}:{self.src_port}" if self.src_port else self.src_ip,
            "dst": f"{self.dst_ip}:{self.dst_port}" if self.dst_port else self.dst_ip,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "proto": self.proto, "service": self.service,
            "packets": self.total_packets, "bytes": self.total_bytes,
            "duration": round(self.duration, 3),
            "flags": f"S{self.syn} SA{self.synack} A{self.ack} F{self.fin} R{self.rst}",
            "label": self.label,
        }

    @property
    def flow_id(self) -> str:
        a, b, proto = self.key
        return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}/{proto}"


def flow_key(rec: dict) -> tuple | None:
    """Canonical direction-independent key for a packet record."""
    if not rec.get("src_ip") or not rec.get("dst_ip"):
        return None
    a = (rec["src_ip"], rec.get("src_port") or 0)
    b = (rec["dst_ip"], rec.get("dst_port") or 0)
    lo, hi = (a, b) if a <= b else (b, a)
    return (lo, hi, rec["proto"])


class FlowTable:
    """Flow store with idle / active timeout eviction."""

    def __init__(self,
                 idle_timeout: float = config.FLOW_IDLE_TIMEOUT,
                 active_timeout: float = config.FLOW_ACTIVE_TIMEOUT,
                 max_flows: int = config.MAX_FLOW_TABLE):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.max_flows = max_flows
        self.flows: dict[tuple, Flow] = {}
        self.completed: list[Flow] = []
        self.total_flows_seen = 0
        self.evicted_count = 0

    # ------------------------------------------------------------ ingest
    def add_packet(self, rec: dict) -> Flow | None:
        key = flow_key(rec)
        if key is None:
            return None

        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(
                key=key,
                src_ip=rec["src_ip"], dst_ip=rec["dst_ip"],
                src_port=rec.get("src_port"), dst_port=rec.get("dst_port"),
                proto=rec["proto"], start_ts=rec["ts"],
            )
            self.flows[key] = flow
            self.total_flows_seen += 1
            if len(self.flows) > self.max_flows:
                self._evict_oldest()

        # forward == same direction as the flow's very first packet
        forward = (rec["src_ip"] == flow.src_ip
                   and (rec.get("src_port") or 0) == (flow.src_port or 0))
        flow.update(rec, forward)
        return flow

    # ------------------------------------------------------------ eviction
    def evict_expired(self, now: float) -> list[Flow]:
        done = []
        for key, flow in list(self.flows.items()):
            idle = now - flow.last_ts
            age = now - flow.start_ts
            reason = None
            if flow.fin >= 2 or flow.rst >= 1:
                reason = "closed (FIN/RST)" if idle > 1.0 else None
            if idle > self.idle_timeout:
                reason = "idle timeout"
            elif age > self.active_timeout:
                reason = "active timeout"
            if reason:
                flow.closed_reason = reason
                done.append(flow)
                del self.flows[key]
        self.completed.extend(done)
        self.evicted_count += len(done)
        if len(self.completed) > 5000:
            self.completed = self.completed[-5000:]
        return done

    def _evict_oldest(self) -> None:
        oldest = min(self.flows.values(), key=lambda f: f.last_ts)
        oldest.closed_reason = "table full"
        self.completed.append(oldest)
        del self.flows[oldest.key]
        self.evicted_count += 1

    def flush(self) -> list[Flow]:
        """Close every open flow — used at the end of a PCAP or a training run."""
        done = list(self.flows.values())
        for f in done:
            f.closed_reason = f.closed_reason or "flush"
        self.flows.clear()
        self.completed.extend(done)
        return done

    # ------------------------------------------------------------ views
    def active(self) -> list[Flow]:
        return list(self.flows.values())

    def all_flows(self) -> list[Flow]:
        return list(self.flows.values()) + self.completed

    def get(self, flow_id: str) -> Flow | None:
        for f in self.all_flows():
            if f.flow_id == flow_id:
                return f
        return None

    def stats(self) -> dict:
        return {
            "active_flows": len(self.flows),
            "completed_flows": len(self.completed),
            "total_flows_seen": self.total_flows_seen,
            "evicted": self.evicted_count,
        }
