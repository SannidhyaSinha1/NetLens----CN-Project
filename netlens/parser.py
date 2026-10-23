"""L2a — per-packet field extraction.

Walks Ether / IP / TCP / UDP / ICMP / ARP / DNS and flattens each packet into a
plain dict ("packet record").  Everything downstream (flows, detectors, UI,
and the synthetic trainer) speaks only this dict, so nothing else in the
project needs to import Scapy.
"""

from __future__ import annotations

import math
from collections import Counter

try:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether

    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - lets the dashboard run without libpcap
    SCAPY_AVAILABLE = False


# ------------------------------------------------------------------ services
PORT_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1883: "MQTT", 3306: "MySQL",
    3389: "RDP", 5353: "mDNS", 5432: "Postgres", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elastic", 27017: "MongoDB",
}

TCP_FLAG_LETTERS = [
    ("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"),
    ("A", "ACK"), ("U", "URG"), ("E", "ECE"), ("C", "CWR"),
]

ICMP_TYPES = {0: "echo-reply", 3: "dest-unreachable", 5: "redirect",
              8: "echo-request", 11: "time-exceeded", 13: "timestamp"}


def service_for(port: int | None, proto: str) -> str:
    """Best-effort service name for a port number."""
    if port is None:
        return proto
    return PORT_SERVICES.get(port, f"{proto}/{port}")


def flag_string(flags: int) -> str:
    """Turn a TCP flag bitfield into the familiar 'SA' / 'PA' / 'FA' string."""
    out = ""
    for bit, letter in zip(
        (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80),
        "FSRPAUEC",
    ):
        if flags & bit:
            out += letter
    return out


def shannon_entropy(text: str) -> float:
    """Bits per character.  Hostnames sit near 3.0; base32/hex payloads >= 4.0."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def blank_record(ts: float) -> dict:
    return {
        "ts": ts,
        "src_mac": None, "dst_mac": None,
        "src_ip": None, "dst_ip": None,
        "proto": "OTHER",
        "src_port": None, "dst_port": None,
        "length": 0, "payload_len": None, "ttl": None,
        "flags": "", "service": "OTHER",
        "dns_qname": None, "dns_qtype": None, "dns_entropy": 0.0,
        "arp_op": None, "icmp_type": None,
        "seq": None, "ack": None, "window": None,
        "label": None,          # only set by the synthetic generator
    }


def parse_packet(pkt, ts: float | None = None) -> dict | None:
    """Flatten one Scapy packet into a packet record.

    Returns None for frames we cannot place in the TCP/IP model at all.
    """
    if not SCAPY_AVAILABLE:
        return None

    rec = blank_record(float(ts if ts is not None else getattr(pkt, "time", 0.0)))
    rec["length"] = len(pkt)

    if Ether in pkt:
        rec["src_mac"] = pkt[Ether].src
        rec["dst_mac"] = pkt[Ether].dst

    # ---------------------------------------------------------- L2: ARP
    if ARP in pkt:
        arp = pkt[ARP]
        rec.update(proto="ARP", src_ip=arp.psrc, dst_ip=arp.pdst,
                   arp_op=int(arp.op), service="ARP",
                   src_mac=arp.hwsrc or rec["src_mac"])
        return rec

    # ---------------------------------------------------------- L3: IP
    if IP in pkt:
        ip = pkt[IP]
        rec.update(src_ip=ip.src, dst_ip=ip.dst, ttl=int(ip.ttl))
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        rec.update(src_ip=ip6.src, dst_ip=ip6.dst, ttl=int(ip6.hlim))
    else:
        rec["proto"] = "L2-ONLY"
        return rec

    # ---------------------------------------------------------- L4
    if TCP in pkt:
        tcp = pkt[TCP]
        rec.update(proto="TCP", src_port=int(tcp.sport), dst_port=int(tcp.dport),
                   flags=flag_string(int(tcp.flags)), seq=int(tcp.seq),
                   ack=int(tcp.ack), window=int(tcp.window),
                   payload_len=len(bytes(tcp.payload)))
    elif UDP in pkt:
        udp = pkt[UDP]
        rec.update(proto="UDP", src_port=int(udp.sport), dst_port=int(udp.dport),
                   payload_len=max(0, int(udp.len) - 8))
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        rec.update(proto="ICMP", icmp_type=int(icmp.type),
                   service=f"ICMP {ICMP_TYPES.get(int(icmp.type), icmp.type)}",
                   payload_len=len(bytes(icmp.payload)))
        return rec
    elif IPv6 in pkt and int(pkt[IPv6].nh) == 58:
        # ICMPv6 is identified by the IPv6 next-header value rather than by a
        # Scapy class, because every ICMPv6 message type is its own class.
        icmp6 = pkt[IPv6].payload
        itype = getattr(icmp6, "type", None)
        rec.update(proto="ICMPv6",
                   icmp_type=int(itype) if itype is not None else None,
                   service="ICMPv6",
                   payload_len=len(bytes(getattr(icmp6, "payload", b""))))
        return rec
    else:
        # A non-initial IP fragment carries no transport header at all, so name
        # the protocol from the IP header and leave the L4 fields unset.
        if IP in pkt:
            name = pkt[IP].get_field("proto").i2s.get(pkt[IP].proto, "IP")
            rec["proto"] = str(name).upper()
        elif IPv6 in pkt:
            rec["proto"] = "IPV6"
        else:
            rec["proto"] = "IP"
        rec["service"] = rec["proto"]
        return rec

    # ---------------------------------------------------------- L7: DNS
    if DNS in pkt:
        dns = pkt[DNS]
        if dns.qd is not None:
            try:
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
            except Exception:
                qname = str(dns.qd.qname)
            labels = qname.split(".")
            longest = max(labels, key=len) if labels else ""
            rec["dns_qname"] = qname
            rec["dns_qtype"] = int(getattr(dns.qd, "qtype", 0) or 0)
            rec["dns_entropy"] = shannon_entropy(longest)

    svc_port = rec["dst_port"] if rec["dst_port"] in PORT_SERVICES else rec["src_port"]
    rec["service"] = service_for(svc_port, rec["proto"])
    return rec
