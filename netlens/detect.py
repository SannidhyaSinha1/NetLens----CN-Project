"""L3 — hybrid analytics engine.

Three tiers run in parallel over the same traffic, and they answer three
different questions:

  Tier 1  RuleEngine        "Does this match a known attack shape?"
          Deterministic, windowed, zero training.  Fan-out port scans,
          half-open SYN floods, DNS-name entropy, ARP MAC/IP conflicts,
          ICMP floods and auth brute force.  Explainable by construction.

  Tier 2  BaselineDetector  "Is this unusual *for this network*?"
          Isolation Forest fitted on the deployment network's own first 60 s
          (novelty N1).  No labels, no signature feed — catches shapes no
          rule anticipated, at the cost of saying nothing about what they are.

  Tier 3  AttackClassifier  "If it is an attack, which one?"
          Random Forest trained offline on labelled flows (`train_model.py`).
          This is the tier that needs malicious examples: an unsupervised
          score can flag a flow as odd, but only a model that has *seen*
          labelled port scans and SYN floods can name one.

Tier 1 gives precision, tier 2 gives coverage, tier 3 gives a name and a
confidence.  An alert that fires on more than one tier is strong evidence;
the dashboard shows which tiers agreed.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

from . import config
from .flows import FEATURE_NAMES

AUTH_PORTS = {21, 22, 23, 3389, 445, 5900, 1433, 3306}


def settled(flow, now: float,
            min_idle: float = config.FLOW_SETTLE_IDLE,
            min_packets: int = config.FLOW_SETTLE_PACKETS) -> bool:
    """Has this flow acquired enough shape to be judged?

    Three ways to qualify, in order of confidence:

    1. The flow is TCP-terminated — FIN from both sides, or a RST.  A finished
       flow has its final shape and can be judged immediately.  This is what
       makes scans and brute-force attempts detectable fast: their probes are
       answered with RST.
    2. It has been idle longer than any plausible human pause.  Covers UDP,
       ICMP and half-open TCP, which never announce an ending.
    3. It already carries `min_packets`, enough shape to judge mid-flight.
       This is what catches floods and bulk transfers early.

    A one-SYN-old web session has the exact feature vector of a SYN-flood
    probe, and a paused SSH session has the exact feature vector of a
    brute-force attempt.  Judging either one early produces a confident wrong
    answer, which is far worse than answering a second later.  The rule tier
    works on packet windows rather than flows, so it still carries the fast
    path while this gate protects the two flow-scoring tiers.
    """
    return (flow.terminated
            or (now - flow.last_ts) >= min_idle
            or flow.total_packets >= min_packets)

# Volumetric attacks forge their source address, so the source is not a stable
# identity — the victim is.  One flood against one target is one event, not
# one event per spoofed source.
VOLUMETRIC_KINDS = {"syn_flood", "icmp_flood"}


@dataclass
class Alert:
    ts: float
    kind: str                 # machine key, also the concept-card key
    title: str
    severity: str             # critical | high | medium | low | info
    source: str               # offending endpoint, host or host:port
    host: str = ""             # offending host alone — the de-duplication key
    target: str = ""
    detail: str = ""
    tier: str = "rule"        # rule | baseline | model
    score: float = 0.0
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    flow_id: str | None = None

    def as_row(self) -> dict:
        return {
            "time": time.strftime("%H:%M:%S", time.localtime(self.ts)),
            "severity": self.severity,
            "alert": self.title,
            "tier": self.tier,
            "source": self.source,
            "target": self.target,
            "confidence": round(self.confidence, 3) if self.confidence else "",
            "detail": self.detail,
        }


# ===================================================================== tier 1
class RuleEngine:
    """Windowed deterministic detectors over raw packet records."""

    def __init__(self, window: float = config.RULE_WINDOW):
        self.window = window
        self.packets: deque = deque()
        self.arp_table: dict[str, str] = {}
        self._last_eval = 0.0

    def observe(self, records: list[dict]) -> None:
        self.packets.extend(records)

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        while self.packets and self.packets[0]["ts"] < cutoff:
            self.packets.popleft()

    def evaluate(self, now: float) -> list[Alert]:
        if now - self._last_eval < 1.0:
            return []
        self._last_eval = now
        self._prune(now)
        if not self.packets:
            return []

        alerts: list[Alert] = []
        ports_by_src: dict[str, set] = defaultdict(set)
        hosts_by_src: dict[str, set] = defaultdict(set)
        hosts_by_src_port: dict[tuple, set] = defaultdict(set)
        syn_by_src: dict[str, int] = defaultdict(int)
        synack_to_src: dict[str, int] = defaultdict(int)
        icmp_by_src: dict[str, int] = defaultdict(int)
        auth_syn_by_src: dict[tuple, int] = defaultdict(int)
        bytes_by_src: dict[str, int] = defaultdict(int)
        # Per-victim aggregation: a real SYN flood forges its source addresses,
        # so per-source counting sees a few SYNs from each of 200 hosts and
        # never crosses a threshold.  The victim is the only stable key.
        syn_by_victim: dict[tuple, int] = defaultdict(int)
        srcs_by_victim: dict[tuple, set] = defaultdict(set)
        synack_from_victim: dict[tuple, int] = defaultdict(int)

        for r in self.packets:
            src, dst, proto = r.get("src_ip"), r.get("dst_ip"), r["proto"]
            if not src:
                continue
            bytes_by_src[src] += r["length"]

            if proto == "TCP":
                flags = r.get("flags") or ""
                dport = r.get("dst_port")
                if "S" in flags and "A" not in flags:
                    syn_by_src[src] += 1
                    if dport is not None:
                        ports_by_src[src].add(dport)
                        hosts_by_src[src].add(dst)
                        hosts_by_src_port[(src, dport)].add(dst)
                        syn_by_victim[(dst, dport)] += 1
                        srcs_by_victim[(dst, dport)].add(src)
                        if dport in AUTH_PORTS:
                            auth_syn_by_src[(src, dport)] += 1
                elif "S" in flags and "A" in flags:
                    synack_to_src[dst] += 1
                    if r.get("src_port") is not None:
                        synack_from_victim[(src, r["src_port"])] += 1

            elif proto == "ICMP" and r.get("icmp_type") == 8:
                icmp_by_src[src] += 1

            elif proto == "ARP":
                mac, ip = r.get("src_mac"), r.get("src_ip")
                if mac and ip and r.get("arp_op") in (1, 2):
                    prev = self.arp_table.get(ip)
                    if prev and prev != mac:
                        alerts.append(Alert(
                            ts=r["ts"], kind="arp_spoof",
                            title="ARP MAC/IP conflict",
                            severity="critical", source=ip, host=ip, target=dst or "",
                            tier="rule",
                            detail=(f"{ip} now claims MAC {mac}, previously {prev}"),
                            evidence={"ip": ip, "new_mac": mac, "old_mac": prev,
                                      "arp_op": r.get("arp_op")}))
                    self.arp_table[ip] = mac

            # ---------------------------------------------- DNS tunnelling
            qname = r.get("dns_qname")
            if qname and r.get("dns_entropy", 0.0) >= config.DNS_ENTROPY_THRESHOLD \
                    and len(qname) >= config.DNS_MIN_QNAME_LEN:
                alerts.append(Alert(
                    ts=r["ts"], kind="dns_tunnel",
                    title="High-entropy DNS query (possible tunnel)",
                    severity="high", source=src, host=src, target=dst or "",
                    tier="rule", score=r["dns_entropy"],
                    detail=(f"{len(qname)}-char name at "
                            f"{r['dns_entropy']:.2f} bits/char — hostnames sit "
                            f"near 3.0, encoded payloads above 3.6"),
                    evidence={"qname": qname[:110],
                              "entropy": round(r["dns_entropy"], 3),
                              "length": len(qname)}))

        # -------------------------------------------------- vertical port scan
        for src, ports in ports_by_src.items():
            if len(ports) >= config.PORTSCAN_MIN_PORTS:
                alerts.append(Alert(
                    ts=now, kind="port_scan",
                    title="Vertical port scan",
                    severity="high", source=src, host=src,
                    target=", ".join(list(hosts_by_src[src])[:3]),
                    tier="rule", score=float(len(ports)),
                    detail=(f"{len(ports)} distinct destination ports probed in "
                            f"{self.window:.0f}s across {len(hosts_by_src[src])} host(s)"),
                    evidence={"distinct_ports": len(ports),
                              "sample_ports": sorted(ports)[:16],
                              "hosts": len(hosts_by_src[src])}))

        # -------------------------------------------------- horizontal sweep
        for (src, port), hosts in hosts_by_src_port.items():
            if len(hosts) >= config.PORTSCAN_MIN_HOSTS:
                alerts.append(Alert(
                    ts=now, kind="host_sweep",
                    title=f"Horizontal sweep on port {port}",
                    severity="high", source=src, host=src, target=f"port {port}",
                    tier="rule", score=float(len(hosts)),
                    detail=(f"{len(hosts)} hosts probed on the same port in "
                            f"{self.window:.0f}s — service discovery sweep"),
                    evidence={"port": port, "hosts": len(hosts),
                              "sample_hosts": sorted(hosts)[:12]}))

        # -------------------------------------------------- SYN flood
        for src, syns in syn_by_src.items():
            replies = synack_to_src.get(src, 0)
            ratio = syns / max(1, replies)
            if syns >= config.SYNFLOOD_MIN_SYNS and ratio >= config.SYNFLOOD_RATIO:
                alerts.append(Alert(
                    ts=now, kind="syn_flood",
                    title="SYN flood / half-open connections",
                    severity="critical", source=src, host=src,
                    target=", ".join(list(hosts_by_src[src])[:3]),
                    tier="rule", score=ratio,
                    detail=(f"{syns} SYNs vs {replies} SYN-ACKs "
                            f"({ratio:.1f}:1) in {self.window:.0f}s — handshakes "
                            f"are being left half-open"),
                    evidence={"syns": syns, "synacks": replies,
                              "ratio": round(ratio, 2)}))

        # -------------------------------------------------- SYN flood (victim side)
        for (victim, port), syns in syn_by_victim.items():
            replies = synack_from_victim.get((victim, port), 0)
            ratio = syns / max(1, replies)
            nsrc = len(srcs_by_victim[(victim, port)])
            if syns >= config.SYNFLOOD_MIN_SYNS and ratio >= config.SYNFLOOD_RATIO:
                distributed = nsrc >= 10
                alerts.append(Alert(
                    ts=now, kind="syn_flood",
                    title=("Distributed SYN flood (spoofed sources)" if distributed
                           else "SYN flood against a service"),
                    severity="critical",
                    source=(f"{nsrc} distinct sources" if distributed
                            else next(iter(srcs_by_victim[(victim, port)]))),
                    host=victim, target=f"{victim}:{port}",
                    tier="rule", score=ratio,
                    detail=(f"{syns} SYNs from {nsrc} source address(es) hit "
                            f"{victim}:{port} in {self.window:.0f}s against only "
                            f"{replies} SYN-ACKs ({ratio:.1f}:1)"
                            + (" — source spread this wide means the addresses "
                               "are forged, which is why counting per source "
                               "would miss this entirely." if distributed
                               else " — handshakes left half-open.")),
                    evidence={"victim": f"{victim}:{port}", "syns": syns,
                              "synacks": replies, "distinct_sources": nsrc,
                              "ratio": round(ratio, 2),
                              "spoofed": distributed}))

        # -------------------------------------------------- ICMP flood
        for src, n in icmp_by_src.items():
            if n >= config.ICMPFLOOD_MIN_PKTS:
                alerts.append(Alert(
                    ts=now, kind="icmp_flood",
                    title="ICMP echo flood",
                    severity="high", source=src, host=src,
                    tier="rule", score=float(n),
                    detail=(f"{n} echo-requests in {self.window:.0f}s "
                            f"({n / self.window:.0f}/s) — far above interactive ping"),
                    evidence={"echo_requests": n,
                              "rate_per_sec": round(n / self.window, 1)}))

        # -------------------------------------------------- brute force
        for (src, port), n in auth_syn_by_src.items():
            if n >= config.BRUTE_MIN_ATTEMPTS:
                alerts.append(Alert(
                    ts=now, kind="brute_force",
                    title=f"Repeated connections to port {port}",
                    severity="high", source=src, host=src, target=f"port {port}",
                    tier="rule", score=float(n),
                    detail=(f"{n} new connections to an authentication service "
                            f"in {self.window:.0f}s — credential guessing pattern"),
                    evidence={"port": port, "attempts": n}))

        return alerts


# ===================================================================== tier 2
class BaselineDetector:
    """Isolation Forest self-baselined on the network's own first 60 seconds."""

    def __init__(self, baseline_seconds: float = config.BASELINE_SECONDS,
                 min_flows: int = config.BASELINE_MIN_FLOWS):
        self.baseline_seconds = baseline_seconds
        self.min_flows = min_flows
        self.started_at: float | None = None
        self.training: list[list[float]] = []
        self.model = None
        self.scaler = None
        self.fitted = False
        self.fit_flow_count = 0
        self.scored = 0
        # flow_id -> packet count at the time we last scored it.  Without this
        # a long flow is re-scored on every tick and a forest calibrated to
        # flag 3% of flows ends up flagging a third of them.
        self._scored_at: dict[str, int] = {}

    @property
    def status(self) -> str:
        if self.fitted:
            return f"baselined on {self.fit_flow_count} local flows"
        if self.started_at is None:
            return "waiting for traffic"
        left = max(0.0, self.baseline_seconds - (time.time() - self.started_at))
        return (f"learning baseline — {len(self.training)} flows, "
                f"{left:.0f}s left")

    def _fit(self) -> None:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        X = np.asarray(self.training, dtype=float)
        self.scaler = StandardScaler().fit(X)
        self.model = IsolationForest(
            n_estimators=200, contamination=config.IFOREST_CONTAMINATION,
            random_state=42, n_jobs=-1,
        ).fit(self.scaler.transform(X))
        self.fitted = True
        self.fit_flow_count = len(X)
        self.training = []

    def process(self, flows: list, now: float) -> list[Alert]:
        if self.started_at is None:
            self.started_at = now
        vectors, keep = [], []
        for f in flows:
            if f.total_packets < 2 or not settled(f, now):
                continue
            if self.fitted:
                seen = self._scored_at.get(f.flow_id)
                # Re-score only if the flow has materially grown since the
                # last verdict; otherwise one flow is one judgement.
                if seen is not None and f.total_packets < seen * 2:
                    continue
                self._scored_at[f.flow_id] = f.total_packets
            vectors.append(f.vector())
            keep.append(f)
        if not vectors:
            return []

        if not self.fitted:
            self.training.extend(vectors)
            elapsed = now - self.started_at
            if (elapsed >= self.baseline_seconds
                    and len(self.training) >= self.min_flows) \
                    or len(self.training) >= config.BASELINE_MAX_FLOWS:
                self._fit()
            return []

        X = self.scaler.transform(np.asarray(vectors, dtype=float))
        scores = self.model.decision_function(X)
        self.scored += len(scores)

        alerts = []
        for f, s in zip(keep, scores):
            if s < config.IFOREST_ALERT_SCORE:
                alerts.append(Alert(
                    ts=now, kind="anomalous_flow",
                    title="Anomalous flow vs local baseline",
                    severity="medium" if s > -0.15 else "high",
                    source=f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip,
                    host=f.src_ip,
                    target=f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip,
                    tier="baseline", score=float(s), flow_id=f.flow_id,
                    detail=(f"Isolation Forest score {s:+.3f} (threshold "
                            f"{config.IFOREST_ALERT_SCORE:+.2f}) — this flow's "
                            f"shape does not resemble the baseline this network "
                            f"established on its own"),
                    evidence={"score": round(float(s), 4),
                              "packets": f.total_packets,
                              "bytes": f.total_bytes,
                              "duration": round(f.duration, 3),
                              "service": f.service}))
        return alerts


# ===================================================================== tier 3
class AttackClassifier:
    """Supervised classifier over flow features — names the attack class.

    Loaded from the bundle written by `train_model.py`.  Absent model file
    simply disables this tier; tiers 1 and 2 keep working.
    """

    def __init__(self, path=config.MODEL_PATH,
                 min_confidence: float = config.SUPERVISED_MIN_CONFIDENCE):
        self.path = path
        self.min_confidence = min_confidence
        self.bundle = None
        self.error: str | None = None
        self._last_class: dict[str, str] = {}
        self.predictions = 0
        self.load()

    def load(self) -> bool:
        try:
            import joblib
            self.bundle = joblib.load(self.path)
            if list(self.bundle.get("features", [])) != list(FEATURE_NAMES):
                self.error = ("Model feature layout differs from the current "
                              "flows.FEATURE_NAMES — retrain with train_model.py")
                self.bundle = None
                return False
            return True
        except FileNotFoundError:
            self.error = (f"No trained model at {self.path} — run "
                          f"`python train_model.py` to train on labelled attacks")
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        return False

    @property
    def available(self) -> bool:
        return self.bundle is not None

    @property
    def status(self) -> str:
        if not self.available:
            return self.error or "unavailable"
        b = self.bundle
        return (f"{b.get('algorithm', 'model')} · "
                f"{len(b['classes'])} classes · "
                f"test accuracy {b.get('test_accuracy', 0):.3f} · "
                f"trained {b.get('trained_at', '?')}")

    def process(self, flows: list, now: float) -> list[Alert]:
        if not self.available:
            return []
        vectors, keep = [], []
        for f in flows:
            if f.total_packets < 1 or not settled(f, now):
                continue
            vectors.append(f.vector())
            keep.append(f)
        if not vectors:
            return []

        b = self.bundle
        X = b["scaler"].transform(np.asarray(vectors, dtype=float))
        proba = b["classifier"].predict_proba(X)
        classes = list(b["classes"])
        self.predictions += len(keep)

        alerts = []
        for f, p in zip(keep, proba):
            idx = int(np.argmax(p))
            label, conf = classes[idx], float(p[idx])
            if label == "benign" or conf < self.min_confidence:
                continue
            if self._last_class.get(f.flow_id) == label:
                continue                       # already reported this verdict
            self._last_class[f.flow_id] = label
            runner_up = sorted(zip(classes, p), key=lambda x: -x[1])[1]
            alerts.append(Alert(
                ts=now, kind=label,
                title=f"{label.replace('_', ' ').title()} (classified)",
                severity="critical" if conf >= 0.9 else "high",
                source=f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip,
                host=f.src_ip,
                target=f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip,
                tier="model", confidence=conf, flow_id=f.flow_id,
                detail=(f"Random Forest assigns '{label}' with {conf:.1%} "
                        f"confidence (next best: {runner_up[0]} "
                        f"{runner_up[1]:.1%}) from {len(FEATURE_NAMES)} flow "
                        f"features"),
                evidence={"predicted_class": label,
                          "confidence": round(conf, 4),
                          "runner_up": f"{runner_up[0]} ({runner_up[1]:.1%})",
                          "packets": f.total_packets,
                          "bytes": f.total_bytes,
                          "duration": round(f.duration, 3),
                          "top_features": self.top_features(f)}))
        return alerts

    def top_features(self, flow, n: int = 5) -> dict:
        """The flow's values for the model's most important features."""
        if not self.available:
            return {}
        imp = self.bundle.get("importances")
        if imp is None:
            return {}
        feats = flow.features()
        order = np.argsort(imp)[::-1][:n]
        return {FEATURE_NAMES[i]: round(float(feats[FEATURE_NAMES[i]]), 3)
                for i in order}


# ===================================================================== hybrid
class HybridDetector:
    """Runs all three tiers and de-duplicates their alerts."""

    def __init__(self, enable_model: bool = True):
        self.rules = RuleEngine()
        self.baseline = BaselineDetector()
        self.classifier = AttackClassifier() if enable_model else None
        self.alerts: list[Alert] = []
        self.counts: dict[str, int] = defaultdict(int)
        self.tier_counts: dict[str, int] = defaultdict(int)
        self._cooldown: dict[tuple, float] = {}

    def _accept(self, alert: Alert) -> bool:
        # Key on the host, not on source:port — a port scan touches hundreds
        # of ports from one attacker and must not produce hundreds of alerts.
        # For volumetric kinds the source is spoofed, so key on the victim.
        identity = (alert.target if alert.kind in VOLUMETRIC_KINDS and alert.target
                    else (alert.host or alert.source))
        key = (alert.kind, identity, alert.tier)
        last = self._cooldown.get(key, 0.0)
        if alert.ts - last < config.ALERT_COOLDOWN:
            return False
        self._cooldown[key] = alert.ts
        return True

    def process(self, records: list[dict], flow_table, now: float | None = None
                ) -> list[Alert]:
        now = now or time.time()
        fresh: list[Alert] = []

        self.rules.observe(records)
        fresh += self.rules.evaluate(now)

        flows = flow_table.active()
        if flows:
            fresh += self.baseline.process(flows, now)
            if self.classifier is not None:
                fresh += self.classifier.process(flows, now)

        new = [a for a in fresh if self._accept(a)]
        for a in new:
            self.counts[a.kind] += 1
            self.tier_counts[a.tier] += 1
        self.alerts = (new + self.alerts)[:config.MAX_ALERTS]
        return new

    def status(self) -> dict:
        return {
            "rules": f"{len(self.rules.packets)} packets in "
                     f"{config.RULE_WINDOW:.0f}s window",
            "baseline": self.baseline.status,
            "model": (self.classifier.status if self.classifier
                      else "disabled"),
            "total_alerts": len(self.alerts),
            "by_tier": dict(self.tier_counts),
            "by_kind": dict(self.counts),
        }
