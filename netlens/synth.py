"""Labelled traffic synthesis — the training ground truth for L3.

Why this module exists
----------------------
The Isolation Forest (novelty N1) needs no labels: it learns "normal" from the
deployment network itself.  But an unsupervised score only answers *"is this
unusual?"*.  To answer *"what kind of attack is this?"* the system needs
examples of attacks that are labelled, and a local campus network does not
hand those out.  So we synthesise them.

Two things make this honest rather than hand-waving:

1. We do not fabricate feature vectors.  We fabricate *packet records* — the
   exact dicts `parser.parse_packet()` emits — and push them through the real
   `flows.FlowTable`.  Every training feature is therefore computed by the same
   code path that computes live features.
2. Nothing is transmitted.  No sockets, no raw frames, no traffic on any
   interface.  This is a dataset builder, not an attack tool.  Real attack
   captures (an isolated lab VM running `nmap -sS` / `hping3`, or CIC-IDS2017
   PCAPs) can be loaded through `replay_pcap()` and mixed in with
   `--extra-pcap` at training time.

Classes produced
----------------
benign           normal web, DNS, bulk transfer, SSH, ping, NTP
port_scan        one SYN per port across many ports, RST-ACK from closed ports
syn_flood        repeated SYNs, never completing the handshake
dns_tunnel       high-entropy encoded labels inside DNS queries
icmp_flood       echo-request storm with almost no replies
ssh_brute_force  many short, complete, low-byte sessions to an auth port
slowloris        complete handshake then trickle packets for minutes
data_exfil       sustained upload where fwd bytes dwarf bwd bytes
"""

from __future__ import annotations

import string

import numpy as np

from .parser import blank_record, service_for, shannon_entropy

ATTACK_CLASSES = [
    "port_scan", "syn_flood", "dns_tunnel", "icmp_flood",
    "ssh_brute_force", "slowloris", "data_exfil",
]
ALL_CLASSES = ["benign"] + ATTACK_CLASSES

LOCAL_NET = "192.168.1."
COMMON_DOMAINS = [
    "google.com", "vit.ac.in", "github.com", "cloudflare.com", "wikipedia.org",
    "youtube.com", "stackoverflow.com", "apple.com", "nptel.ac.in", "zoom.us",
    "office365.com", "pypi.org", "fonts.gstatic.com", "api.weather.gov",
]
EPHEMERAL = (32768, 60999)


# --------------------------------------------------------------- primitives
def _rec(ts, proto, sip, dip, length, label, *, sport=None, dport=None,
         flags="", ttl=64, payload_len=0, seq=None, ack=None,
         dns_qname=None, icmp_type=None, src_mac=None, dst_mac=None):
    r = blank_record(float(ts))
    r.update(proto=proto, src_ip=sip, dst_ip=dip, src_port=sport, dst_port=dport,
             length=int(length), flags=flags, ttl=ttl,
             payload_len=int(payload_len), seq=seq, ack=ack,
             src_mac=src_mac, dst_mac=dst_mac, icmp_type=icmp_type,
             label=label)
    if dns_qname:
        longest = max(dns_qname.split("."), key=len)
        r["dns_qname"] = dns_qname
        r["dns_entropy"] = shannon_entropy(longest)
        r["dns_qtype"] = 16 if len(longest) > 30 else 1
    r["service"] = service_for(dport if dport in (22, 53, 80, 443) else sport, proto)
    return r


def _local_ip(rng) -> str:
    return LOCAL_NET + str(int(rng.integers(2, 254)))


def _remote_ip(rng) -> str:
    return ".".join(str(int(x)) for x in rng.integers(1, 223, size=4))


def _eph(rng) -> int:
    return int(rng.integers(*EPHEMERAL))


def _handshake(ts, rng, cli, srv, sport, dport, label, ttl_c=64, ttl_s=None):
    """SYN -> SYN-ACK -> ACK, with realistic sub-RTT gaps."""
    ttl_s = ttl_s if ttl_s is not None else int(rng.integers(48, 64))
    rtt = float(rng.uniform(0.002, 0.08))
    seq = int(rng.integers(1, 2**31))
    out = [
        _rec(ts, "TCP", cli, srv, 74, label, sport=sport, dport=dport,
             flags="S", ttl=ttl_c, seq=seq, ack=0),
        _rec(ts + rtt, "TCP", srv, cli, 74, label, sport=dport, dport=sport,
             flags="SA", ttl=ttl_s, seq=int(rng.integers(1, 2**31)), ack=seq + 1),
        _rec(ts + rtt * 1.4, "TCP", cli, srv, 66, label, sport=sport, dport=dport,
             flags="A", ttl=ttl_c, seq=seq + 1),
    ]
    return out, ts + rtt * 1.4, rtt


def _teardown(ts, rng, cli, srv, sport, dport, label, graceful=True):
    if graceful:
        gap = float(rng.uniform(0.001, 0.05))
        return [
            _rec(ts, "TCP", cli, srv, 66, label, sport=sport, dport=dport, flags="FA"),
            _rec(ts + gap, "TCP", srv, cli, 66, label, sport=dport, dport=sport, flags="FA"),
            _rec(ts + gap * 1.5, "TCP", cli, srv, 66, label, sport=sport, dport=dport, flags="A"),
        ]
    return [_rec(ts, "TCP", cli, srv, 66, label, sport=sport, dport=dport, flags="RA")]


# --------------------------------------------------------------- benign
def benign_web(rng, t0):
    """HTTPS page load: handshake, request, a burst of MSS-sized replies, FIN."""
    lab = "benign"
    cli, srv = _local_ip(rng), _remote_ip(rng)
    sport, dport = _eph(rng), int(rng.choice([443, 443, 443, 80, 8443]))
    recs, t, rtt = _handshake(t0, rng, cli, srv, sport, dport, lab)

    for _ in range(int(rng.integers(1, 5))):                 # request/response turns
        t += float(rng.uniform(0.005, 0.4))
        req = int(rng.integers(200, 1200))
        recs.append(_rec(t, "TCP", cli, srv, req + 66, lab, sport=sport, dport=dport,
                         flags="PA", payload_len=req))
        nresp = int(rng.integers(3, 40))
        for i in range(nresp):
            t += float(rng.uniform(0.0005, 0.02))
            size = int(rng.choice([1514, 1514, 1514, rng.integers(200, 1400)]))
            recs.append(_rec(t, "TCP", srv, cli, size, lab, sport=dport, dport=sport,
                             flags="PA" if i == nresp - 1 else "A",
                             payload_len=size - 66, ttl=int(rng.integers(48, 64))))
            if i % 3 == 2:                                    # client ACKs the window
                t += 0.0004
                recs.append(_rec(t, "TCP", cli, srv, 66, lab, sport=sport,
                                 dport=dport, flags="A"))
    t += float(rng.uniform(0.01, 0.6))
    recs += _teardown(t, rng, cli, srv, sport, dport, lab, graceful=rng.random() > 0.15)
    return recs


def benign_dns(rng, t0):
    lab = "benign"
    cli, srv = _local_ip(rng), rng.choice(["192.168.1.1", "8.8.8.8", "1.1.1.1"])
    sport = _eph(rng)
    name = str(rng.choice(COMMON_DOMAINS))
    if rng.random() < 0.3:
        name = rng.choice(["www", "api", "cdn", "mail"]) + "." + name
    q = int(len(name) + 45)
    rtt = float(rng.uniform(0.004, 0.12))
    return [
        _rec(t0, "UDP", cli, str(srv), q, lab, sport=sport, dport=53,
             payload_len=q - 42, dns_qname=name),
        _rec(t0 + rtt, "UDP", str(srv), cli, q + int(rng.integers(16, 90)), lab,
             sport=53, dport=sport, dns_qname=name, ttl=int(rng.integers(52, 64))),
    ]


def benign_bulk(rng, t0):
    """iperf3 / file download: long, MSS-saturated, handshake complete."""
    lab = "benign"
    cli, srv = _local_ip(rng), _remote_ip(rng)
    sport, dport = _eph(rng), int(rng.choice([443, 80, 5201, 21]))
    recs, t, rtt = _handshake(t0, rng, cli, srv, sport, dport, lab)
    n = int(rng.integers(150, 900))
    gap = float(rng.uniform(0.0002, 0.004))
    for i in range(n):
        t += abs(float(rng.normal(gap, gap * 0.4)))
        recs.append(_rec(t, "TCP", srv, cli, 1514, lab, sport=dport, dport=sport,
                         flags="A", payload_len=1448, ttl=int(rng.integers(48, 64))))
        if i % 2 == 1:
            recs.append(_rec(t + 1e-4, "TCP", cli, srv, 66, lab, sport=sport,
                             dport=dport, flags="A"))
    recs += _teardown(t + 0.01, rng, cli, srv, sport, dport, lab)
    return recs


def benign_ssh(rng, t0):
    """Interactive SSH: small packets both ways, human-paced gaps."""
    lab = "benign"
    cli, srv = _local_ip(rng), _local_ip(rng)
    sport = _eph(rng)
    recs, t, rtt = _handshake(t0, rng, cli, srv, sport, 22, lab)
    for _ in range(int(rng.integers(20, 120))):
        t += abs(float(rng.normal(0.6, 0.5))) + 0.01
        n = int(rng.integers(30, 120))
        recs.append(_rec(t, "TCP", cli, srv, n + 66, lab, sport=sport, dport=22,
                         flags="PA", payload_len=n))
        t += float(rng.uniform(0.001, 0.05))
        m = int(rng.integers(40, 900))
        recs.append(_rec(t, "TCP", srv, cli, m + 66, lab, sport=22, dport=sport,
                         flags="PA", payload_len=m))
    recs += _teardown(t + 0.2, rng, cli, srv, sport, 22, lab)
    return recs


def benign_ping(rng, t0):
    lab = "benign"
    cli, srv = _local_ip(rng), rng.choice(["192.168.1.1", "8.8.8.8"])
    recs = []
    t = t0
    for _ in range(int(rng.integers(3, 10))):
        rtt = float(rng.uniform(0.002, 0.06))
        recs.append(_rec(t, "ICMP", cli, str(srv), 98, lab, icmp_type=8))
        recs.append(_rec(t + rtt, "ICMP", str(srv), cli, 98, lab, icmp_type=0,
                         ttl=int(rng.integers(50, 64))))
        t += 1.0 + float(rng.uniform(-0.02, 0.02))
    return recs


def benign_ntp(rng, t0):
    lab = "benign"
    cli, srv = _local_ip(rng), _remote_ip(rng)
    sport = _eph(rng)
    rtt = float(rng.uniform(0.01, 0.2))
    return [
        _rec(t0, "UDP", cli, srv, 90, lab, sport=sport, dport=123, payload_len=48),
        _rec(t0 + rtt, "UDP", srv, cli, 90, lab, sport=123, dport=sport,
             payload_len=48, ttl=int(rng.integers(48, 64))),
    ]


BENIGN_SCENARIOS = [
    (benign_web, 0.34), (benign_dns, 0.26), (benign_bulk, 0.10),
    (benign_ssh, 0.10), (benign_ping, 0.10), (benign_ntp, 0.10),
]


# --------------------------------------------------------------- attacks
def port_scan(rng, t0):
    """nmap -sS: one SYN per port, closed ports answer RST-ACK.

    Each probed port is its own flow, so one scan contributes many tiny flows —
    exactly how a flow-based tool sees it.
    """
    lab = "port_scan"
    att, tgt = _local_ip(rng), _local_ip(rng)
    sport_base = _eph(rng)
    nports = int(rng.integers(40, 400))
    ports = rng.choice(np.arange(1, 10000), size=nports, replace=False)
    gap = float(rng.uniform(0.0004, 0.01))     # nmap default is aggressive
    recs, t = [], t0
    for i, p in enumerate(ports):
        t += abs(float(rng.normal(gap, gap * 0.5)))
        sp = (sport_base + i) % 65535 or 1024
        recs.append(_rec(t, "TCP", att, tgt, 58, lab, sport=sp, dport=int(p),
                         flags="S", ttl=int(rng.choice([64, 128, 255])), seq=0))
        roll = rng.random()
        if roll < 0.80:                         # closed port -> RST-ACK
            recs.append(_rec(t + float(rng.uniform(0.0002, 0.004)), "TCP", tgt, att,
                             60, lab, sport=int(p), dport=sp, flags="RA"))
        elif roll < 0.90:                       # open port -> SYN-ACK, then abort
            rtt = float(rng.uniform(0.0003, 0.005))
            recs.append(_rec(t + rtt, "TCP", tgt, att, 74, lab, sport=int(p),
                             dport=sp, flags="SA"))
            recs.append(_rec(t + rtt * 2, "TCP", att, tgt, 54, lab, sport=sp,
                             dport=int(p), flags="R"))
        # else: filtered -> no reply at all
    return recs


def syn_flood(rng, t0):
    """hping3 -S --flood: SYNs with spoofed sources, handshake never completes."""
    lab = "syn_flood"
    tgt = _local_ip(rng)
    dport = int(rng.choice([80, 443, 22, 3306, 8080]))
    nsrc = int(rng.integers(30, 200))
    gap = float(rng.uniform(0.00002, 0.0008))
    recs, t = [], t0
    for _ in range(nsrc):
        spoof = _remote_ip(rng)
        sport = _eph(rng)
        for _ in range(int(rng.integers(1, 7))):      # retransmitted SYNs
            t += abs(float(rng.normal(gap, gap * 0.6)))
            recs.append(_rec(t, "TCP", spoof, tgt, 58, lab, sport=sport,
                             dport=dport, flags="S",
                             ttl=int(rng.choice([64, 128, 255, 48])), seq=0))
        if rng.random() < 0.25:                        # backlog SYN-ACK, never ACKed
            recs.append(_rec(t + float(rng.uniform(0.001, 0.02)), "TCP", tgt, spoof,
                             74, lab, sport=dport, dport=sport, flags="SA"))
    return recs


def dns_tunnel(rng, t0):
    """iodine-style tunnel: base32 payload smuggled in the query label."""
    lab = "dns_tunnel"
    cli, srv = _local_ip(rng), _remote_ip(rng)
    sport = _eph(rng)
    zone = rng.choice(["t.evil-c2.net", "tun.exfil.io", "dns.badactor.xyz"])
    alphabet = string.ascii_lowercase + string.digits
    recs, t = [], t0
    for _ in range(int(rng.integers(20, 160))):
        t += abs(float(rng.normal(0.08, 0.05))) + 0.002
        chunk_len = int(rng.integers(40, 63))
        chunk = "".join(rng.choice(list(alphabet), size=chunk_len))
        name = f"{chunk}.{zone}"
        q = len(name) + 45
        recs.append(_rec(t, "UDP", cli, srv, q, lab, sport=sport, dport=53,
                         payload_len=q - 42, dns_qname=name))
        if rng.random() < 0.95:                       # big TXT answer carries data back
            resp = int(rng.integers(180, 500))
            recs.append(_rec(t + float(rng.uniform(0.01, 0.15)), "UDP", srv, cli,
                             resp, lab, sport=53, dport=sport,
                             payload_len=resp - 42, dns_qname=name,
                             ttl=int(rng.integers(40, 60))))
    return recs


def icmp_flood(rng, t0):
    """ping -f: echo-request storm, replies cannot keep up."""
    lab = "icmp_flood"
    att, tgt = _remote_ip(rng), _local_ip(rng)
    n = int(rng.integers(120, 900))
    gap = float(rng.uniform(0.00005, 0.002))
    size = int(rng.choice([98, 98, 1514, 342]))
    recs, t = [], t0
    for i in range(n):
        t += abs(float(rng.normal(gap, gap * 0.5)))
        recs.append(_rec(t, "ICMP", att, tgt, size, lab, icmp_type=8,
                         ttl=int(rng.choice([64, 128, 255]))))
        if rng.random() < 0.08:
            recs.append(_rec(t + float(rng.uniform(0.0001, 0.003)), "ICMP", tgt,
                             att, size, lab, icmp_type=0))
    return recs


def ssh_brute_force(rng, t0):
    """hydra against sshd: many complete but tiny sessions, mostly reset."""
    lab = "ssh_brute_force"
    att, tgt = _remote_ip(rng), _local_ip(rng)
    dport = int(rng.choice([22, 22, 22, 3389, 21]))
    recs, t = [], t0
    for _ in range(int(rng.integers(15, 90))):
        sport = _eph(rng)
        attempt, t2, rtt = _handshake(t, rng, att, tgt, sport, dport, lab,
                                      ttl_c=int(rng.choice([64, 128])))
        recs += attempt
        tt = t2
        for _ in range(int(rng.integers(2, 6))):      # banner + credential exchange
            tt += float(rng.uniform(0.005, 0.12))
            n = int(rng.integers(40, 300))
            recs.append(_rec(tt, "TCP", att, tgt, n + 66, lab, sport=sport,
                             dport=dport, flags="PA", payload_len=n))
            tt += float(rng.uniform(0.002, 0.06))
            m = int(rng.integers(40, 200))
            recs.append(_rec(tt, "TCP", tgt, att, m + 66, lab, sport=dport,
                             dport=sport, flags="PA", payload_len=m))
        recs += _teardown(tt + 0.01, rng, att, tgt, sport, dport, lab,
                          graceful=rng.random() < 0.25)   # auth failure -> RST
        t = tt + float(rng.uniform(0.02, 0.5))
    return recs


def slowloris(rng, t0):
    """Half-open HTTP: handshake completes, then one partial header per minute."""
    lab = "slowloris"
    att, tgt = _remote_ip(rng), _local_ip(rng)
    dport = int(rng.choice([80, 443, 8080]))
    sport = _eph(rng)
    recs, t, rtt = _handshake(t0, rng, att, tgt, sport, dport, lab)
    for _ in range(int(rng.integers(4, 20))):
        t += float(rng.uniform(8.0, 25.0))            # deliberately glacial
        n = int(rng.integers(8, 40))
        recs.append(_rec(t, "TCP", att, tgt, n + 66, lab, sport=sport, dport=dport,
                         flags="PA", payload_len=n))
        if rng.random() < 0.5:
            recs.append(_rec(t + float(rng.uniform(0.001, 0.05)), "TCP", tgt, att,
                             66, lab, sport=dport, dport=sport, flags="A"))
    return recs


def data_exfil(rng, t0):
    """Sustained outbound upload — direction ratio is the giveaway."""
    lab = "data_exfil"
    cli, srv = _local_ip(rng), _remote_ip(rng)
    sport, dport = _eph(rng), int(rng.choice([443, 8080, 4444, 9001, 53]))
    recs, t, rtt = _handshake(t0, rng, cli, srv, sport, dport, lab)
    n = int(rng.integers(200, 1200))
    gap = float(rng.uniform(0.002, 0.03))
    for i in range(n):
        t += abs(float(rng.normal(gap, gap * 0.3)))
        recs.append(_rec(t, "TCP", cli, srv, 1514, lab, sport=sport, dport=dport,
                         flags="PA", payload_len=1448))
        if i % 8 == 7:                                 # server only ACKs
            recs.append(_rec(t + 1e-3, "TCP", srv, cli, 66, lab, sport=dport,
                             dport=sport, flags="A", ttl=int(rng.integers(40, 60))))
    recs += _teardown(t + 0.05, rng, cli, srv, sport, dport, lab)
    return recs


ATTACK_SCENARIOS = {
    "port_scan": port_scan,
    "syn_flood": syn_flood,
    "dns_tunnel": dns_tunnel,
    "icmp_flood": icmp_flood,
    "ssh_brute_force": ssh_brute_force,
    "slowloris": slowloris,
    "data_exfil": data_exfil,
}


# --------------------------------------------------------------- dataset build
def _scenario_flows(fn, rng, t0, table_cls):
    """Run one scenario in its own flow table so labels stay clean."""
    table = table_cls()
    for rec in sorted(fn(rng, t0), key=lambda r: r["ts"]):
        table.add_packet(rec)
    return table.flush()


def build_dataset(flows_per_class: int = 700, seed: int = 42, verbose: bool = True):
    """Generate a balanced, labelled flow dataset.

    Returns (pandas.DataFrame of features + label, meta dict).
    """
    import pandas as pd

    from .flows import FEATURE_NAMES, FlowTable

    rng = np.random.default_rng(seed)
    rows, counts = [], {c: 0 for c in ALL_CLASSES}
    t0 = 1_700_000_000.0

    def emit(flows):
        for f in flows:
            if f.total_packets < 1 or f.label is None:
                continue
            if counts[f.label] >= flows_per_class:
                continue
            feats = f.features()
            feats["label"] = f.label
            feats["proto_name"] = f.proto
            feats["service"] = f.service
            rows.append(feats)
            counts[f.label] += 1

    guard = 0
    while min(counts.values()) < flows_per_class and guard < 200_000:
        guard += 1
        t0 += float(rng.uniform(0.5, 5.0))

        if counts["benign"] < flows_per_class:
            fns, w = zip(*BENIGN_SCENARIOS)
            fn = fns[int(rng.choice(len(fns), p=np.array(w) / sum(w)))]
            emit(_scenario_flows(fn, rng, t0, FlowTable))

        for name in ATTACK_CLASSES:
            if counts[name] < flows_per_class:
                emit(_scenario_flows(ATTACK_SCENARIOS[name], rng, t0, FlowTable))

        if verbose and guard % 25 == 0:
            done = sum(counts.values())
            print(f"  ... {done} flows  "
                  + "  ".join(f"{k[:9]}={v}" for k, v in counts.items()),
                  flush=True)

    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    meta = {"counts": counts, "features": FEATURE_NAMES, "classes": ALL_CLASSES,
            "seed": seed, "rounds": guard}
    return df, meta


def replay_pcap(path, label=None, bpf=None):
    """Yield packet records from a real capture file (optionally labelled).

    Lets real lab captures — `nmap`/`hping3` runs in an isolated VM, or public
    PCAPs such as CIC-IDS2017 — be mixed into the same training pipeline.
    """
    from scapy.utils import rdpcap

    from .parser import parse_packet

    for pkt in rdpcap(str(path)):
        rec = parse_packet(pkt)
        if rec is None:
            continue
        rec["label"] = label
        yield rec


# --------------------------------------------------------------- live sim
class TrafficSimulator:
    """Wall-clock traffic source for demos without raw-socket privileges.

    Emits the same packet records a real NIC would, on a real timeline, so the
    dashboard, the flow table and all three detectors run their genuine code
    paths.  Attacks can be injected on demand from the sidebar.
    """

    def __init__(self, seed: int | None = None, benign_rate: float = 2.5,
                 attack_every: tuple[float, float] = (25.0, 70.0),
                 auto_attacks: bool = True):
        import heapq  # noqa: F401  (kept local; see _push)

        self.rng = np.random.default_rng(seed)
        self.benign_rate = benign_rate          # scenarios started per second
        self.auto_attacks = auto_attacks
        self.attack_every = attack_every
        self._pending: list = []                # heap of (ts, seq, rec)
        self._seq = 0
        self._next_benign = 0.0
        self._next_attack = 0.0
        self.injected: list[str] = []
        self.packets_emitted = 0

    # ------------------------------------------------------------ internals
    def _push(self, recs, now):
        import heapq
        if not recs:
            return
        base = min(r["ts"] for r in recs)
        for r in recs:
            r["ts"] = now + (r["ts"] - base)
            self._seq += 1
            heapq.heappush(self._pending, (r["ts"], self._seq, r))

    def _spawn_benign(self, now):
        fns, w = zip(*BENIGN_SCENARIOS)
        fn = fns[int(self.rng.choice(len(fns), p=np.array(w) / sum(w)))]
        self._push(fn(self.rng, 0.0), now)

    def _spawn_attack(self, now, name=None):
        name = name or str(self.rng.choice(ATTACK_CLASSES))
        self._push(ATTACK_SCENARIOS[name](self.rng, 0.0), now)
        return name

    # ------------------------------------------------------------ api
    def inject(self, name: str) -> str:
        """Queue one attack scenario immediately (sidebar button)."""
        import time
        got = self._spawn_attack(time.time(), name)
        self.injected.append(got)
        return got

    def poll(self) -> list[dict]:
        """Return every record whose scheduled time has arrived."""
        import heapq
        import time
        now = time.time()

        if self._next_benign == 0.0:
            self._next_benign = now
            self._next_attack = now + float(self.rng.uniform(*self.attack_every))

        while self._next_benign <= now:
            self._spawn_benign(self._next_benign)
            self._next_benign += float(self.rng.exponential(1.0 / self.benign_rate))

        if self.auto_attacks and self._next_attack <= now:
            self.injected.append(self._spawn_attack(now))
            self._next_attack = now + float(self.rng.uniform(*self.attack_every))

        out = []
        while self._pending and self._pending[0][0] <= now:
            out.append(heapq.heappop(self._pending)[2])
        self.packets_emitted += len(out)
        return out

    def stats(self) -> dict:
        return {"queued": len(self._pending), "emitted": self.packets_emitted,
                "attacks_injected": len(self.injected)}
