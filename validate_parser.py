#!/usr/bin/env python3
"""Phase-2 validation: cross-check parser.py field-by-field against tshark.

    python validate_parser.py                      # build reference pcap, validate
    python validate_parser.py --pcap captures/real.pcap
    python validate_parser.py --keep-pcap          # keep the generated capture

What this proves
----------------
`netlens/parser.py` walks the layers itself rather than trusting a helper, so
the only way to know its field extraction is right is to compare it with the
reference dissector on identical bytes.  Every frame is decoded twice — once by
tshark, once by our parser — and each field is compared value by value.

The reference capture is built to contain the cases that actually break naive
parsers, not just happy-path traffic:

  * TCP options (MSS/SACK/timestamps) — payload length must not absorb them
  * a pure ACK (zero payload) next to a full-MSS segment
  * every flag combination: SYN, SYN-ACK, PSH-ACK, FIN-ACK, RST, RST-ACK, URG
  * an ICMP destination-unreachable that *embeds* the original IP+TCP header,
    so the frame contains two IP layers and two port pairs
  * a second IP fragment, which carries no TCP header at all
  * a VLAN-tagged frame, where the IP layer is not where it usually sits
  * IPv6 TCP and UDP, where TTL lives in a differently named field
  * DNS with both a normal hostname and a 60-char high-entropy label
  * TTLs at 1, 64, 128 and 255

A real capture can be validated the same way with --pcap; nothing here is
specific to the generated file.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from netlens import config
from netlens.parser import flag_string, parse_packet

TSHARK_CANDIDATES = [
    "tshark",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/local/bin/tshark",
    "/opt/homebrew/bin/tshark",
    "/usr/bin/tshark",
]

# tshark field -> how we read it.  First value only: a frame that embeds another
# packet (ICMP unreachable) reports some fields twice, and our parser
# deliberately describes the outer packet.
TSHARK_FIELDS = [
    "frame.number", "frame.len",
    "eth.src", "eth.dst",
    "ip.src", "ip.dst", "ip.ttl", "ip.proto",
    "ipv6.src", "ipv6.dst", "ipv6.hlim",
    "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "tcp.srcport", "tcp.dstport", "tcp.flags", "tcp.seq_raw", "tcp.ack_raw",
    "tcp.len", "tcp.window_size_value",
    "udp.srcport", "udp.dstport", "udp.length",
    "icmp.type", "icmpv6.type",
    "dns.qry.name",
]


def find_tshark(override: str | None = None) -> str:
    for cand in ([override] if override else []) + TSHARK_CANDIDATES:
        if not cand:
            continue
        path = shutil.which(cand) or (cand if Path(cand).is_file() else None)
        if path:
            return path
    sys.exit("tshark not found. Install Wireshark, or pass --tshark /path/to/tshark")


# ===================================================================== pcap
def build_reference_pcap(path: Path) -> int:
    """Construct a capture covering the cases that break naive parsers."""
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
    from scapy.layers.l2 import ARP, Dot1Q, Ether
    from scapy.utils import wrpcap

    cli_mac, srv_mac = "aa:bb:cc:00:11:22", "de:ad:be:ef:00:01"
    cli, srv = "192.168.1.50", "93.184.216.34"
    eth = Ether(src=cli_mac, dst=srv_mac)
    rev = Ether(src=srv_mac, dst=cli_mac)
    pkts = []

    # --- ARP: who-has and is-at
    pkts.append(Ether(src=cli_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op=1, hwsrc=cli_mac, psrc=cli, pdst="192.168.1.1"))
    pkts.append(Ether(src=srv_mac, dst=cli_mac)
                / ARP(op=2, hwsrc=srv_mac, psrc="192.168.1.1", pdst=cli))

    # --- TCP handshake, with options on the SYN (MSS/SACK/timestamps)
    seq = 1_000_000
    pkts.append(eth / IP(src=cli, dst=srv, ttl=64)
                / TCP(sport=51514, dport=443, flags="S", seq=seq, window=65535,
                      options=[("MSS", 1460), ("SAckOK", b""),
                               ("Timestamp", (123456, 0)), ("NOP", None),
                               ("WScale", 7)]))
    pkts.append(rev / IP(src=srv, dst=cli, ttl=55)
                / TCP(sport=443, dport=51514, flags="SA", seq=7_000_000,
                      ack=seq + 1, window=28960,
                      options=[("MSS", 1380), ("SAckOK", b""),
                               ("Timestamp", (999, 123456))]))
    pkts.append(eth / IP(src=cli, dst=srv, ttl=64)
                / TCP(sport=51514, dport=443, flags="A", seq=seq + 1,
                      ack=7_000_001, window=2048))

    # --- payload-bearing segments: full MSS, small PSH, and a bare ACK
    pkts.append(eth / IP(src=cli, dst=srv, ttl=64)
                / TCP(sport=51514, dport=443, flags="PA", seq=seq + 1,
                      ack=7_000_001) / (b"X" * 517))
    pkts.append(rev / IP(src=srv, dst=cli, ttl=55)
                / TCP(sport=443, dport=51514, flags="A", seq=7_000_001,
                      ack=seq + 518,
                      options=[("Timestamp", (1000, 123457))]) / (b"Y" * 1448))
    pkts.append(eth / IP(src=cli, dst=srv, ttl=64)
                / TCP(sport=51514, dport=443, flags="A", seq=seq + 518,
                      ack=7_001_449))

    # --- the remaining flag combinations
    for flags, ttl in (("FA", 64), ("R", 128), ("RA", 255), ("UA", 64),
                       ("FPA", 64)):
        pkts.append(eth / IP(src=cli, dst=srv, ttl=ttl)
                    / TCP(sport=51514, dport=443, flags=flags, seq=seq + 519,
                          ack=7_001_449, urgptr=1 if "U" in flags else 0))

    # --- DNS: ordinary hostname, then a long high-entropy label
    pkts.append(eth / IP(src=cli, dst="192.168.1.1", ttl=64)
                / UDP(sport=40000, dport=53)
                / DNS(rd=1, qd=DNSQR(qname="www.example.com", qtype="A")))
    pkts.append(Ether(src=srv_mac, dst=cli_mac)
                / IP(src="192.168.1.1", dst=cli, ttl=64)
                / UDP(sport=53, dport=40000)
                / DNS(qr=1, qd=DNSQR(qname="www.example.com"),
                      an=DNSRR(rrname="www.example.com", rdata="93.184.216.34")))
    tunnel = "k3n9v2qp7xz4mw8rt5hj6bd1fg0sy" "a7c3e9u2i4o8l6n0" "qv5zx3mw9"
    pkts.append(eth / IP(src=cli, dst="203.0.113.9", ttl=64)
                / UDP(sport=40001, dport=53)
                / DNS(rd=1, qd=DNSQR(qname=f"{tunnel}.t.evil-c2.net",
                                     qtype="TXT")))

    # --- ICMP echo pair, and an unreachable that embeds the original headers
    pkts.append(eth / IP(src=cli, dst="8.8.8.8", ttl=1)
                / ICMP(type=8, id=4242, seq=1) / (b"Z" * 56))
    pkts.append(Ether(src=srv_mac, dst=cli_mac)
                / IP(src="8.8.8.8", dst=cli, ttl=117)
                / ICMP(type=0, id=4242, seq=1) / (b"Z" * 56))
    pkts.append(Ether(src=srv_mac, dst=cli_mac)
                / IP(src="192.168.1.1", dst=cli, ttl=64)
                / ICMP(type=3, code=3)
                / IP(src=cli, dst=srv, ttl=64) / TCP(sport=51514, dport=443))

    # --- NTP and mDNS over UDP
    pkts.append(eth / IP(src=cli, dst="216.239.35.0", ttl=64)
                / UDP(sport=40002, dport=123) / (b"\x23" + b"\x00" * 47))
    pkts.append(Ether(src=cli_mac, dst="01:00:5e:00:00:fb")
                / IP(src=cli, dst="224.0.0.251", ttl=255)
                / UDP(sport=5353, dport=5353)
                / DNS(rd=0, qd=DNSQR(qname="_printer._tcp.local", qtype="PTR")))

    # --- a second IP fragment: no TCP header in this frame at all
    pkts.append(eth / IP(src=cli, dst=srv, ttl=64, proto=6, frag=185,
                         flags=0) / (b"F" * 600))

    # --- VLAN-tagged: the IP layer is not where it normally sits
    pkts.append(Ether(src=cli_mac, dst=srv_mac) / Dot1Q(vlan=42)
                / IP(src=cli, dst=srv, ttl=64)
                / TCP(sport=51515, dport=80, flags="S", seq=5, window=512))

    # --- IPv6 TCP and UDP, plus an ICMPv6 echo
    v6c, v6s = "2001:db8::50", "2001:db8::1"
    pkts.append(eth / IPv6(src=v6c, dst=v6s, hlim=64)
                / TCP(sport=51516, dport=443, flags="S", seq=99, window=64240))
    pkts.append(eth / IPv6(src=v6c, dst=v6s, hlim=63)
                / UDP(sport=51517, dport=53)
                / DNS(rd=1, qd=DNSQR(qname="ipv6.example.net", qtype="AAAA")))
    pkts.append(eth / IPv6(src=v6c, dst=v6s, hlim=64) / ICMPv6EchoRequest())

    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.0 + i * 0.01

    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), pkts)
    return len(pkts)


# ===================================================================== tshark
def run_tshark(tshark: str, pcap: Path) -> list[dict]:
    cmd = [tshark, "-r", str(pcap), "-n", "-T", "fields",
           "-E", "separator=|", "-E", "occurrence=f",
           "-o", "tcp.relative_sequence_numbers:FALSE",
           "-o", "tcp.calculate_timestamps:FALSE"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"tshark failed:\n{res.stderr}")
    rows = []
    for line in res.stdout.splitlines():
        if not line.strip():
            continue
        vals = line.split("|")
        vals += [""] * (len(TSHARK_FIELDS) - len(vals))
        rows.append({f: v.strip() for f, v in zip(TSHARK_FIELDS, vals)})
    return rows


# ===================================================================== compare
def tshark_view(t: dict) -> dict:
    """Normalise tshark's fields into our packet-record vocabulary."""
    def num(v):
        if v == "":
            return None
        try:
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        except ValueError:
            return None

    src_ip = t["ip.src"] or t["ipv6.src"] or t["arp.src.proto_ipv4"] or None
    dst_ip = t["ip.dst"] or t["ipv6.dst"] or t["arp.dst.proto_ipv4"] or None
    ttl = num(t["ip.ttl"]) if t["ip.ttl"] else num(t["ipv6.hlim"])

    sport = num(t["tcp.srcport"]) if t["tcp.srcport"] else num(t["udp.srcport"])
    dport = num(t["tcp.dstport"]) if t["tcp.dstport"] else num(t["udp.dstport"])

    flags = ""
    if t["tcp.flags"]:
        flags = flag_string(num(t["tcp.flags"]) & 0xFF)

    if t["tcp.len"] != "":
        payload = num(t["tcp.len"])
    elif t["udp.length"] != "":
        payload = max(0, (num(t["udp.length"]) or 0) - 8)
    else:
        payload = None

    icmp_type = (num(t["icmp.type"]) if t["icmp.type"]
                 else num(t["icmpv6.type"]) if t["icmpv6.type"] else None)

    return {
        "length": num(t["frame.len"]),
        "src_mac": (t["eth.src"] or None),
        "dst_mac": (t["eth.dst"] or None),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ttl": ttl,
        "src_port": sport,
        "dst_port": dport,
        "flags": flags,
        "seq": num(t["tcp.seq_raw"]),
        "ack": num(t["tcp.ack_raw"]),
        "window": num(t["tcp.window_size_value"]),
        "payload_len": payload,
        "icmp_type": icmp_type,
        "arp_op": num(t["arp.opcode"]),
        "dns_qname": (t["dns.qry.name"] or None),
    }


def ours_view(rec: dict) -> dict:
    keys = ("length", "src_mac", "dst_mac", "src_ip", "dst_ip", "ttl",
            "src_port", "dst_port", "flags", "seq", "ack", "window",
            "payload_len", "icmp_type", "arp_op", "dns_qname")
    out = {k: rec.get(k) for k in keys}
    for k in ("src_mac", "dst_mac"):
        if out[k]:
            out[k] = out[k].lower()
    if out["dns_qname"]:
        out["dns_qname"] = out["dns_qname"].rstrip(".").lower()
    return out


# Fields that cannot be meaningfully compared for a given protocol.  Skipped
# with a stated reason rather than quietly counted as passes.
#
# The ICMP cases are the interesting ones.  An ICMP error message *quotes* the
# header of the packet that caused it, so a destination-unreachable frame
# contains a second IP header and a second port pair.  tshark reports those
# quoted values under tcp.srcport / tcp.flags / tcp.window, because they are
# the only TCP fields in the frame.  Our parser deliberately describes the
# outer frame — the thing that was actually transmitted — and leaves the
# transport fields unset.  Both are correct; they are answering different
# questions, so comparing them proves nothing.
_QUOTED = ("tshark reads the header quoted inside the ICMP error; the parser "
           "describes the outer frame")
SKIP = {
    ("payload_len", "ICMP"): "parser measures ICMP data; tshark exposes it "
                             "under a different field",
    ("payload_len", "ICMPv6"): "same, for ICMPv6",
}
for _f in ("src_port", "dst_port", "flags", "seq", "ack", "window"):
    SKIP[(_f, "ICMP")] = _QUOTED
    SKIP[(_f, "ICMPv6")] = _QUOTED


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", type=Path,
                    help="validate an existing capture instead of generating one")
    ap.add_argument("--tshark", help="path to the tshark binary")
    ap.add_argument("--keep-pcap", action="store_true")
    ap.add_argument("--max-show", type=int, default=12)
    args = ap.parse_args()

    tshark = find_tshark(args.tshark)
    lines: list[str] = []

    def out(s=""):
        print(s, flush=True)
        lines.append(str(s))

    out("=" * 78)
    out("NetLens Phase-2 validation — parser.py vs tshark, field by field")
    out("=" * 78)
    out(f"tshark: {tshark}")

    if args.pcap:
        pcap, generated = args.pcap, False
        if not pcap.is_file():
            sys.exit(f"no such capture: {pcap}")
        out(f"capture: {pcap} (supplied)")
    else:
        pcap, generated = config.CAPTURE_DIR / "reference.pcap", True
        n = build_reference_pcap(pcap)
        out(f"capture: {pcap} (generated, {n} frames covering TCP options, "
            f"fragments,")
        out(f"         VLAN tags, IPv6, embedded headers and DNS edge cases)")
    out("")

    ref_rows = run_tshark(tshark, pcap)

    from scapy.utils import rdpcap
    packets = rdpcap(str(pcap))
    if len(packets) != len(ref_rows):
        out(f"!! frame count mismatch: tshark {len(ref_rows)}, "
            f"scapy {len(packets)}")
        return 1
    out(f"frames decoded by both: {len(packets)}")
    out("")

    checked = defaultdict(int)
    mismatched = defaultdict(int)
    skipped = defaultdict(int)
    failures = []

    for i, (pkt, trow) in enumerate(zip(packets, ref_rows), start=1):
        rec = parse_packet(pkt, ts=float(getattr(pkt, "time", 0.0)))
        if rec is None:
            failures.append((i, "-", "parser returned None", "frame decoded"))
            mismatched["<frame>"] += 1
            continue
        mine, theirs = ours_view(rec), tshark_view(trow)
        proto = rec["proto"]

        for field in theirs:
            reason = SKIP.get((field, proto))
            if reason:
                skipped[f"{field} ({proto})"] += 1
                continue
            a, b = mine[field], theirs[field]
            # tshark omits a field entirely when the layer is absent; our parser
            # reports None for the same case. Agreeing on "absent" is agreement.
            if a is None and b is None:
                continue
            if a in ("", None) and b in ("", None):
                continue
            checked[field] += 1
            if str(a).lower() != str(b).lower():
                mismatched[field] += 1
                failures.append((i, field, a, b))

    width = max(len(f) for f in checked) if checked else 12
    out(f"{'field':<{width}}  {'compared':>9}  {'agree':>7}  {'differ':>7}")
    out("-" * (width + 30))
    total_c = total_m = 0
    for field in sorted(checked):
        c, m = checked[field], mismatched[field]
        total_c += c
        total_m += m
        flag = "" if m == 0 else "   <-- see below"
        out(f"{field:<{width}}  {c:>9}  {c - m:>7}  {m:>7}{flag}")
    out("-" * (width + 30))
    out(f"{'TOTAL':<{width}}  {total_c:>9}  {total_c - total_m:>7}  "
        f"{total_m:>7}")
    out("")

    if skipped:
        out("fields not compared (parser does not claim them for that protocol)")
        for k, v in sorted(skipped.items()):
            base = k.split(" ")[0]
            proto = k.split("(")[1].rstrip(")")
            out(f"  {k:<22} ×{v} — {SKIP[(base, proto)]}")
        out("")

    if failures:
        out(f"mismatches ({len(failures)}, showing up to {args.max_show})")
        out(f"  {'frame':>5}  {'field':<14} {'parser.py':<28} tshark")
        for frame, field, a, b in failures[:args.max_show]:
            out(f"  {frame:>5}  {field:<14} {str(a):<28} {b}")
        if len(failures) > args.max_show:
            out(f"  ... {len(failures) - args.max_show} more")
        out("")

    agreement = (total_c - total_m) / total_c if total_c else 0.0
    out(f"agreement: {agreement:.4%} over {total_c} field comparisons "
        f"across {len(packets)} frames")
    verdict = "PASS" if total_m == 0 else "FAIL"
    out(f"{verdict} — parser.py {'matches' if total_m == 0 else 'DIVERGES from'} "
        f"the reference dissector")

    rp = config.DATA_DIR / "parser_validation.txt"
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text("\n".join(lines) + "\n")
    print(f"report  -> {rp}")

    if generated and not args.keep_pcap:
        out_note = f"(kept {pcap} so the check is reproducible)"
        print(out_note)

    return 0 if total_m == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
