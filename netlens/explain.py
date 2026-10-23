"""L4 — explanation layer.

Two jobs, both aimed at the "explainable" requirement in the problem statement:

1. CONCEPTS — a registry that binds every chart and every alert kind to the
   networking principle it evidences, so no number on the dashboard is shown
   without the protocol behaviour that produced it.
2. build_ladder() — rebuilds a chosen flow as a timestamped sequence diagram
   from the actual captured packets (novelty N3), turning the textbook
   three-way handshake into something observed rather than described.
"""

from __future__ import annotations

FLAG_NAMES = {
    "S": "SYN", "SA": "SYN-ACK", "A": "ACK", "PA": "PSH-ACK", "FA": "FIN-ACK",
    "F": "FIN", "R": "RST", "RA": "RST-ACK", "FPA": "FIN-PSH-ACK",
    "UA": "URG-ACK", "SEC": "SYN-ECE-CWR",
}


def flag_label(flags: str) -> str:
    if not flags:
        return ""
    return FLAG_NAMES.get(flags, "-".join(
        {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
         "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}.get(c, c)
        for c in flags))


# ===================================================================== cards
CONCEPTS: dict[str, dict] = {
    # ------------------------------------------------- dashboard metrics
    "protocol_mix": {
        "title": "Protocol distribution",
        "concept": "Layered encapsulation in the TCP/IP model",
        "observed": "Share of captured frames per L4 protocol (TCP/UDP/ICMP/ARP).",
        "why": ("Every frame carries a stack of headers; the mix tells you what "
                "the network is being used for. Interactive and bulk traffic is "
                "TCP, name resolution and streaming lean UDP, and a sudden ICMP "
                "or ARP spike is almost never ordinary user activity."),
        "where": "RFC 1122 · host requirements, layering",
    },
    "throughput": {
        "title": "Throughput and packet rate",
        "concept": "Bandwidth vs packet rate are different limits",
        "observed": "Bytes/s and packets/s computed over the capture window.",
        "why": ("A link saturates on bytes, a device saturates on packets. Many "
                "small packets (floods, scans) can exhaust CPU and interrupt "
                "budget while barely touching the bandwidth number."),
        "where": "Compare bytes/s against packets/s in the KPI strip",
    },
    "flow": {
        "title": "What a flow is",
        "concept": "Bidirectional 5-tuple conversation",
        "observed": ("Packets grouped by (src IP, src port, dst IP, dst port, "
                     "protocol), with both directions in one record."),
        "why": ("Routers and NAT tables track conversations, not packets. Flow "
                "aggregation is also what makes statistical features possible: "
                "a single packet has no duration, no ratio and no rhythm."),
        "where": "RFC 7011 · IPFIX flow definition",
    },
    "flow_timeout": {
        "title": "Flow timeouts",
        "concept": "Idle vs active eviction",
        "observed": "Idle 15 s, active 120 s, then the flow is closed and scored.",
        "why": ("TCP tells you when it is finished (FIN/RST); UDP and ICMP never "
                "do. Timeouts bound memory and give every flow an end, which is "
                "required before duration-based features mean anything."),
        "where": "Flow table panel · 'closed reason' column",
    },
    "top_talkers": {
        "title": "Top talkers",
        "concept": "Traffic is heavily skewed",
        "observed": "Byte and packet totals per host, ranked.",
        "why": ("Normal networks have a few heavy hosts (gateway, DNS resolver, "
                "update servers) and a long thin tail. A host that appears at "
                "the top without a reason — or a host talking to unusually many "
                "peers — is the first thing to investigate."),
        "where": "Top talkers chart",
    },
    "ports": {
        "title": "Ports and services",
        "concept": "Transport-layer demultiplexing",
        "observed": "Destination port counts mapped to well-known service names.",
        "why": ("A port is how one IP address hosts many services. Ports below "
                "1024 are the registered services; ephemeral high ports are the "
                "client side. Traffic to an unexpected service port is a strong "
                "signal on its own."),
        "where": "RFC 6335 · IANA port registry",
    },

    # ------------------------------------------------- protocol behaviour
    "three_way_handshake": {
        "title": "TCP three-way handshake",
        "concept": "Connection establishment and sequence-number sync",
        "observed": "SYN → SYN-ACK → ACK, with the RTT visible between steps.",
        "why": ("Both sides exchange initial sequence numbers and confirm the "
                "other is reachable and willing. The gap between SYN and "
                "SYN-ACK is one round trip — the cheapest latency measurement "
                "on the wire. A SYN with no SYN-ACK means filtered, closed or "
                "unreachable; many of those from one host is a scan."),
        "where": "RFC 9293 §3.5 · session ladder, steps 1-3",
    },
    "tcp_teardown": {
        "title": "Connection teardown",
        "concept": "Graceful FIN exchange vs abortive RST",
        "observed": "FIN-ACK both ways and a final ACK, or a single RST.",
        "why": ("FIN means 'I have no more data' and each side closes "
                "independently — hence two FINs. RST is an abort: refused "
                "ports, killed processes and failed authentication all produce "
                "one, which is why RST density is a useful feature."),
        "where": "RFC 9293 §3.6 · end of the session ladder",
    },
    "retransmission": {
        "title": "Retransmission",
        "concept": "Reliable delivery through ACK timeouts",
        "observed": "The same sequence number sent again after no ACK arrived.",
        "why": ("TCP's reliability is retransmission, and retransmissions are "
                "how loss becomes visible: the application only sees slowness, "
                "the packet stream shows exactly which segment was lost and how "
                "long recovery took."),
        "where": "RFC 6298 · RTO computation",
    },
    "dns_resolution": {
        "title": "DNS resolution",
        "concept": "Name to address lookup before any connection",
        "observed": "A UDP/53 query followed by a response with the same name.",
        "why": ("Nearly every session starts with a DNS lookup, so DNS is both "
                "a map of user intent and an excellent covert channel — the "
                "query name is attacker-controlled text that firewalls usually "
                "allow straight out."),
        "where": "RFC 1035 · query/response format",
    },
    "tls_handshake": {
        "title": "TLS and encrypted payloads",
        "concept": "Metadata survives encryption",
        "observed": "Port 443 flows whose payload bytes are opaque.",
        "why": ("With TLS, payload inspection is blind — which is exactly why "
                "this project analyses flow behaviour. Sizes, directions, "
                "timing and handshake shape remain fully readable and are "
                "enough to characterise a connection."),
        "where": "RFC 8446 · TLS 1.3",
    },
    "ttl": {
        "title": "Time To Live",
        "concept": "Hop-count loop prevention",
        "observed": "Mean TTL per flow; initial values are 64, 128 or 255.",
        "why": ("Each router decrements TTL, so the distance from the common "
                "initial values estimates hop count. Mixed or odd TTLs inside "
                "one conversation suggest spoofed sources or an injected path."),
        "where": "RFC 791 · IP header",
    },
    "mtu_fragmentation": {
        "title": "MTU and fragmentation",
        "concept": "Link-layer size limits",
        "observed": "Packet-length histogram clustering at ~1514 B and ~66 B.",
        "why": ("Ethernet's 1500-byte MTU produces the classic bimodal size "
                "distribution: full-MSS data segments at the top, bare ACKs at "
                "the bottom. Flows that sit entirely in the middle are usually "
                "interactive or deliberately slow."),
        "where": "RFC 1191 · path MTU discovery",
    },
    "arp": {
        "title": "ARP",
        "concept": "IP to MAC binding on the local segment",
        "observed": "who-has / is-at exchanges and the IP→MAC table built from them.",
        "why": ("ARP has no authentication whatsoever: any host can answer for "
                "any address. That is what makes the IP→MAC map worth watching "
                "— a changed binding is either DHCP churn or an attacker "
                "positioning as a man in the middle."),
        "where": "RFC 826 · address resolution",
    },
    "icmp": {
        "title": "ICMP",
        "concept": "Control and diagnostic messaging for IP",
        "observed": "Echo request/reply pairs and unreachable messages.",
        "why": ("ICMP carries the signalling IP itself cannot: ping measures "
                "reachability, time-exceeded powers traceroute, and "
                "unreachable reports path failures. It is also trivially "
                "abusable as a flood or a covert channel."),
        "where": "RFC 792 · ICMP",
    },

    # ------------------------------------------------- alert kinds
    "port_scan": {
        "title": "Port scan",
        "concept": "Reconnaissance via handshake probing",
        "observed": ("One source sending SYNs to many ports, each answered by "
                     "RST-ACK (closed) or SYN-ACK (open), or ignored (filtered)."),
        "why": ("A SYN scan never completes the handshake — it reads the reply "
                "and abandons the attempt, so each probe is a 1-2 packet flow "
                "with no data. Harmless individually; as fan-out from one host "
                "it is an attacker mapping the attack surface."),
        "where": "Session ladder shows SYN → RST-ACK with no data phase",
    },
    "host_sweep": {
        "title": "Horizontal sweep",
        "concept": "Service discovery across a subnet",
        "observed": "One source probing the same port on many hosts.",
        "why": ("The transpose of a port scan: instead of 'what is open on this "
                "host', it asks 'who runs this service'. Typically the step "
                "right before targeted exploitation of a known-vulnerable "
                "service."),
        "where": "Rule tier · distinct destination hosts per port",
    },
    "syn_flood": {
        "title": "SYN flood",
        "concept": "Exhausting the half-open connection backlog",
        "observed": "SYNs far outnumbering SYN-ACKs, final ACK never arriving.",
        "why": ("The server allocates state on SYN and holds it waiting for the "
                "ACK that never comes. With spoofed sources the backlog fills "
                "and legitimate handshakes are refused. The SYN:SYN-ACK ratio "
                "is the direct measurement of this."),
        "where": "RFC 4987 · SYN flooding mitigations",
    },
    "dns_tunnel": {
        "title": "DNS tunnelling",
        "concept": "Data smuggled inside query names",
        "observed": ("Long query labels at 3.6+ bits/char entropy, with large "
                     "TXT answers returning data."),
        "why": ("Real hostnames are pronounceable and repetitive (~3.0 "
                "bits/char); base32-encoded payload is near-uniform (4.5+). "
                "Since DNS is almost always permitted outbound, encoding data "
                "into the name is a reliable exfiltration and C2 channel."),
        "where": "Alert evidence shows the query name and its entropy",
    },
    "icmp_flood": {
        "title": "ICMP flood",
        "concept": "Volumetric denial of service",
        "observed": "Echo-requests at hundreds per second with few replies.",
        "why": ("No connection state is needed, so the only limit is bandwidth "
                "and interrupt handling. Interactive ping is one packet per "
                "second — three orders of magnitude below this."),
        "where": "Rule tier · echo-requests per window",
    },
    "brute_force": {
        "title": "Credential brute force",
        "concept": "Repeated authentication attempts",
        "observed": ("Many short, complete connections to an auth port (22, 3389, "
                     "445), most ending in RST."),
        "why": ("Each guess needs its own full session: handshake, a few hundred "
                "bytes of protocol, then an abrupt close on failure. The shape "
                "— complete handshake, tiny byte count, RST close, high "
                "repetition — is unmistakable at flow level."),
        "where": "Flow table · repeated short flows to one port",
    },
    "ssh_brute_force": {
        "title": "SSH brute force",
        "concept": "Credential guessing against SSH",
        "observed": "Dozens of sub-second port-22 sessions from one source.",
        "why": ("SSH authentication happens after the handshake, so failures "
                "still cost a full TCP connection. That makes the attack "
                "visible without reading a single encrypted byte."),
        "where": "Model tier · classified from flow features",
    },
    "slowloris": {
        "title": "Slowloris",
        "concept": "Resource exhaustion by holding connections open",
        "observed": ("Completed handshake, then tiny partial-header packets "
                     "minutes apart; very long duration, almost no bytes."),
        "why": ("The opposite of a flood: it looks like an extremely slow client, "
                "so volume thresholds never trigger. Each socket is held "
                "waiting for a request that is never finished, until the server "
                "runs out of worker slots."),
        "where": "Flow features · high duration, near-zero bytes/s",
    },
    "data_exfil": {
        "title": "Data exfiltration",
        "concept": "Directional byte asymmetry",
        "observed": "Sustained upload where forward bytes dwarf reverse bytes.",
        "why": ("Normal client traffic downloads far more than it uploads. A "
                "long flow pushing megabytes outward with only ACKs coming "
                "back inverts that expectation, regardless of the port it uses "
                "or whether the payload is encrypted."),
        "where": "Flow features · down_up_bytes_ratio near zero",
    },
    "arp_spoof": {
        "title": "ARP spoofing",
        "concept": "Poisoning the IP→MAC mapping",
        "observed": "One IP address claimed by a second MAC address.",
        "why": ("Because ARP replies are unauthenticated, an attacker can claim "
                "the gateway's IP and have the segment's traffic delivered to "
                "them first — a man-in-the-middle position obtained with a "
                "single forged frame."),
        "where": "Rule tier · IP→MAC table conflict",
    },
    "anomalous_flow": {
        "title": "Statistical anomaly (label-free)",
        "concept": "Unsupervised outlier detection",
        "observed": ("Isolation Forest score below threshold, where the forest "
                     "was fitted on this network's own first 60 seconds."),
        "why": ("An isolation tree needs fewer random splits to separate an "
                "outlier than a typical point, so 'how easily isolated' becomes "
                "an anomaly score with no labels required. It defines normal "
                "locally — which is why it works on a network it has never seen "
                "— but it can only say 'unusual', never 'this is a SYN flood'. "
                "That is the job of the supervised tier."),
        "where": "Baseline tier · score in the alert evidence",
    },
    "model_tier": {
        "title": "Why the model needs malicious examples",
        "concept": "Unsupervised vs supervised detection",
        "observed": ("Tier 2 scores novelty with no labels; tier 3 assigns a "
                     "named class with a confidence."),
        "why": ("Anomaly detection answers 'is this unlike normal?'. It cannot "
                "answer 'what is it?', because nothing ever told it what a port "
                "scan looks like. To name an attack, the model has to have seen "
                "labelled attacks — so we synthesise packet-level attack "
                "scenarios, push them through the same flow pipeline as live "
                "traffic, and train a Random Forest on the resulting labelled "
                "feature vectors. Benign-only anomaly detection and "
                "label-trained classification answer different questions, which "
                "is why NetLens runs both."),
        "where": "train_model.py · evaluate.py report",
    },
}


def concept_for(key: str) -> dict:
    return CONCEPTS.get(key, {
        "title": key.replace("_", " ").title(),
        "concept": "—",
        "observed": "—",
        "why": "No concept card registered for this item yet.",
        "where": "",
    })


# ===================================================================== ladder
def build_ladder(flow) -> list[dict]:
    """Reconstruct a flow as an annotated, timestamped sequence diagram."""
    if not flow or not flow.ladder:
        return []

    t0 = flow.ladder[0]["ts"]
    steps, phase, seen = [], "setup", {"S": False, "SA": False, "A": False}

    for i, p in enumerate(flow.ladder):
        flags = p["flags"]
        label = flag_label(flags) or p["proto"]
        note = ""

        if p["proto"] == "TCP":
            if flags == "S":
                seen["S"] = True
                phase = "handshake"
                note = "client opens: proposes its initial sequence number"
            elif "S" in flags and "A" in flags:
                seen["SA"] = True
                note = (f"server accepts and acknowledges "
                        f"(RTT {(p['ts'] - t0) * 1000:.1f} ms)")
            elif flags == "A" and seen["SA"] and not seen["A"]:
                seen["A"] = True
                phase = "established"
                note = "handshake complete — connection established"
            elif p["payload_len"] > 0:
                # A data segment usually has only ACK set — PSH marks the end of
                # a burst, not the presence of data. Labelling a 1448-byte
                # segment "acknowledgement only" would be plainly wrong.
                phase = "data"
                note = f"carries {p['payload_len']} B of payload"
            elif "P" in flags:
                phase = "data"
                note = "push, no payload"
            elif "R" in flags:
                phase = "aborted"
                note = "abortive close — refused, reset or failed auth"
            elif "F" in flags:
                phase = "teardown"
                note = "this side has no more data to send"
            elif flags == "A":
                note = "acknowledgement only"
        elif p["proto"] == "UDP":
            phase = "data"
            label = "DNS query" if p.get("dns_qname") and p["forward"] else (
                "DNS response" if p.get("dns_qname") else "UDP datagram")
            if p.get("dns_qname"):
                note = p["dns_qname"][:70]
        elif p["proto"] == "ICMP":
            phase = "data"
            label = {8: "Echo request", 0: "Echo reply",
                     3: "Dest unreachable", 11: "Time exceeded"}.get(
                p.get("icmp_type"), f"ICMP type {p.get('icmp_type')}")

        steps.append({
            "n": i + 1,
            "t_ms": round((p["ts"] - t0) * 1000, 3),
            "direction": "->" if p["forward"] else "<-",
            "arrow": "client -> server" if p["forward"] else "server -> client",
            "label": label,
            "flags": flags,
            "bytes": p["length"],
            "payload": p["payload_len"],
            "phase": phase,
            "note": note,
        })

    return steps


def interpret_flow(flow) -> dict:
    """Plain-language reading of what this flow actually did."""
    if flow is None:
        return {}

    f, lines, concepts = flow.features(), [], []

    if flow.proto == "TCP":
        if flow.handshake_complete:
            lines.append("Three-way handshake completed — a real session existed.")
            concepts.append("three_way_handshake")
        elif flow.syn and not flow.synack:
            lines.append("SYN sent, no SYN-ACK returned: port closed, filtered, "
                         "or host unreachable. One of these is a failed "
                         "connection; hundreds is reconnaissance.")
            concepts.append("port_scan")
        elif flow.syn and flow.synack and flow.ack < 2:
            lines.append("Server answered SYN-ACK but the client never sent the "
                         "final ACK — a half-open connection, which is what a "
                         "SYN flood leaves behind.")
            concepts.append("syn_flood")

        if flow.rst:
            lines.append(f"{flow.rst} RST packet(s): the connection was aborted "
                         f"rather than closed gracefully.")
            concepts.append("tcp_teardown")
        elif flow.fin >= 2:
            lines.append("Both sides sent FIN — graceful bidirectional close.")
            concepts.append("tcp_teardown")

        if flow.dst_port in (443, 8443):
            lines.append("Port 443: payload is TLS-encrypted, so this flow is "
                         "characterised entirely by its metadata.")
            concepts.append("tls_handshake")

    elif flow.proto == "UDP":
        if flow.dst_port == 53 or flow.dns_qnames:
            lines.append("DNS traffic — connectionless request/response with no "
                         "handshake to observe.")
            concepts.append("dns_resolution")
            if flow.dns_entropy_max >= 3.6:
                lines.append(f"Query-name entropy reaches "
                             f"{flow.dns_entropy_max:.2f} bits/char — far above "
                             f"real hostnames, consistent with encoded payload.")
                concepts.append("dns_tunnel")
    elif flow.proto == "ICMP":
        lines.append("ICMP: diagnostic messaging, no ports and no connection state.")
        concepts.append("icmp")
    elif flow.proto == "ARP":
        lines.append("ARP: link-layer address resolution, local segment only.")
        concepts.append("arp")

    ratio = f["down_up_bytes_ratio"]
    if flow.total_bytes > 50_000 and ratio < 0.1:
        lines.append(f"Byte ratio {ratio:.3f} — almost entirely outbound, which "
                     f"inverts normal client behaviour.")
        concepts.append("data_exfil")
    elif ratio > 8:
        lines.append(f"Byte ratio {ratio:.1f} — download-dominated, the usual "
                     f"shape for web and media traffic.")

    if f["duration"] > 60 and f["bytes_per_sec"] < 200 and flow.handshake_complete:
        lines.append(f"Open {f['duration']:.0f}s at only "
                     f"{f['bytes_per_sec']:.0f} B/s — a connection held open "
                     f"without doing work.")
        concepts.append("slowloris")

    if f["max_pkt_len"] >= 1400:
        concepts.append("mtu_fragmentation")
    if flow.ttls.n and (flow.ttls.std > 20):
        lines.append(f"TTL varies by {flow.ttls.std:.0f} within one flow — "
                     f"inconsistent path or spoofed sources.")
        concepts.append("ttl")

    if not lines:
        lines.append("Short, unremarkable exchange with no distinguishing "
                     "protocol behaviour.")

    return {"lines": lines, "concepts": list(dict.fromkeys(concepts))}
