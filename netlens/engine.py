"""Pipeline orchestration — the producer/consumer seam (novelty N4).

The dashboard is a rerun-based UI: Streamlit re-executes the script on every
refresh.  If capture lived inside that script it would restart constantly and
lose packets.  So capture runs on its own thread behind a bounded ring buffer,
and the UI only ever calls `Engine.tick()`, which drains whatever has arrived
since last time and advances L2-L4.  Capture rate and refresh rate are
therefore completely independent.

Everything the dashboard renders comes off this object, so the UI holds no
analysis logic of its own.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict, deque

from . import config
from .detect import HybridDetector
from .flows import FlowTable


class Engine:
    def __init__(self, source, enable_model: bool = True,
                 enable_rules: bool = True, enable_baseline: bool = True):
        self.source = source
        self.flows = FlowTable()
        self.detector = HybridDetector(enable_model=enable_model)
        self.enable_rules = enable_rules
        self.enable_baseline = enable_baseline

        self.started_at = time.time()
        self.last_tick = 0.0
        self.tick_count = 0
        self.tick_ms = deque(maxlen=120)        # UI-side processing latency

        self.packets = 0
        self.bytes = 0
        self.proto_counts: Counter = Counter()
        self.port_counts: Counter = Counter()
        self.service_counts: Counter = Counter()
        self.talker_bytes: Counter = Counter()
        self.talker_packets: Counter = Counter()
        self.pair_bytes: Counter = Counter()
        self.size_hist: Counter = Counter()      # bucketed packet sizes
        self.timeline: dict[int, list] = defaultdict(lambda: [0, 0])
        self.recent: deque = deque(maxlen=400)   # packet log for the UI
        self.ttl_counts: Counter = Counter()

    # ------------------------------------------------------------ control
    def start(self) -> None:
        self.source.start()
        self.started_at = time.time()

    def stop(self) -> None:
        self.source.stop()

    # ------------------------------------------------------------ main loop
    def tick(self) -> dict:
        """Drain the ring buffer and advance the pipeline. Called by the UI."""
        t_start = time.perf_counter()
        records = self.source.poll()
        now = time.time()

        for rec in records:
            self.packets += 1
            self.bytes += rec["length"]
            self.proto_counts[rec["proto"]] += 1
            if rec.get("dst_port") is not None:
                self.port_counts[rec["dst_port"]] += 1
            self.service_counts[rec.get("service") or rec["proto"]] += 1
            if rec.get("src_ip"):
                self.talker_bytes[rec["src_ip"]] += rec["length"]
                self.talker_packets[rec["src_ip"]] += 1
            if rec.get("src_ip") and rec.get("dst_ip"):
                self.pair_bytes[(rec["src_ip"], rec["dst_ip"])] += rec["length"]
            if rec.get("ttl") is not None:
                self.ttl_counts[rec["ttl"]] += 1

            self.size_hist[min(1600, (rec["length"] // 100) * 100)] += 1

            bucket = int(rec["ts"])
            self.timeline[bucket][0] += 1
            self.timeline[bucket][1] += rec["length"]

            self.flows.add_packet(rec)
            self.recent.append(rec)

        # L2 eviction, then L3 over the current flow set
        self.flows.evict_expired(now)
        new_alerts = self.detector.process(records, self.flows, now=now)

        # bound the timeline
        cutoff = int(now) - config.TIMELINE_WINDOW * 3
        for k in [k for k in self.timeline if k < cutoff]:
            del self.timeline[k]

        self.last_tick = now
        self.tick_count += 1
        self.tick_ms.append((time.perf_counter() - t_start) * 1000)
        return {"records": len(records), "alerts": len(new_alerts)}

    # ------------------------------------------------------------ views
    @property
    def elapsed(self) -> float:
        return max(1e-3, time.time() - self.started_at)

    def kpis(self) -> dict:
        src = self.source.stats()
        recent_pps = recent_bps = 0.0
        now = int(time.time())
        window = [self.timeline[s] for s in range(now - 10, now) if s in self.timeline]
        if window:
            recent_pps = sum(w[0] for w in window) / len(window)
            recent_bps = sum(w[1] for w in window) / len(window)
        return {
            "packets": self.packets,
            "bytes": self.bytes,
            "pps_avg": self.packets / self.elapsed,
            "pps_now": recent_pps,
            "bps_now": recent_bps,
            "elapsed": self.elapsed,
            "active_flows": len(self.flows.flows),
            "total_flows": self.flows.total_flows_seen,
            "alerts": len(self.detector.alerts),
            "dropped": src.get("dropped", 0),
            "drop_rate": src.get("drop_rate", 0.0),
            "buffered": src.get("buffered", 0),
            "tick_ms": (sum(self.tick_ms) / len(self.tick_ms)) if self.tick_ms else 0.0,
            "source": src.get("source"),
            "error": src.get("error"),
        }

    def timeline_series(self, window: int = config.TIMELINE_WINDOW):
        now = int(time.time())
        secs = list(range(now - window, now + 1))
        return (secs,
                [self.timeline.get(s, [0, 0])[0] for s in secs],
                [self.timeline.get(s, [0, 0])[1] for s in secs])

    def top_talkers(self, n: int = config.TOP_N):
        return self.talker_bytes.most_common(n)

    def top_ports(self, n: int = config.TOP_N):
        from .parser import PORT_SERVICES
        return [(f"{p} ({PORT_SERVICES.get(p, '?')})" if p in PORT_SERVICES
                 else str(p), c) for p, c in self.port_counts.most_common(n)]

    def flow_rows(self, limit: int = 300, only_flagged: bool = False):
        flagged = {a.flow_id for a in self.detector.alerts if a.flow_id}
        by_flow = {}
        for a in self.detector.alerts:
            if a.flow_id and a.flow_id not in by_flow:
                by_flow[a.flow_id] = a

        rows = []
        pool = sorted(self.flows.all_flows(), key=lambda f: -f.last_ts)
        for f in pool:
            if only_flagged and f.flow_id not in flagged:
                continue
            a = by_flow.get(f.flow_id)
            rows.append({
                "flow_id": f.flow_id,
                "source": f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip,
                "destination": f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip,
                "proto": f.proto,
                "service": f.service,
                "packets": f.total_packets,
                "bytes": f.total_bytes,
                "duration_s": round(f.duration, 3),
                "fwd/bwd": f"{f.fwd_packets}/{f.bwd_packets}",
                "tcp_flags": (f"S{f.syn} SA{f.synack} A{f.ack} "
                              f"F{f.fin} R{f.rst}") if f.proto == "TCP" else "",
                "state": f.closed_reason or "active",
                "verdict": (a.title if a else ""),
                "tier": (a.tier if a else ""),
            })
            if len(rows) >= limit:
                break
        return rows

    def status(self) -> dict:
        s = self.detector.status()
        s["flow_table"] = self.flows.stats()
        s["capture"] = self.source.stats()
        return s
