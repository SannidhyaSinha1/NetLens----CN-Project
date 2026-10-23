# NetLens — Network Packet Analyzer with Visual Dashboard

Computer Networks · Project Review 2
Sannidhya Sinha (24BCI0192) · Avishi Sharma (24BCI0118)

Captures live traffic, aggregates it into bidirectional flows, derives 37
statistical features per flow, flags abnormal behaviour through three
independent detector tiers, and explains every number it shows in terms of the
protocol behaviour that produced it.

---

## Quick start

**Double-click `NetLens.command`** in Finder. That is the whole thing.

It checks the environment, installs anything missing, trains the classifier if
there is no model yet, starts the dashboard and opens it in your browser. The
first run takes a few minutes because of the dependency install and training;
every run after that is a few seconds.

Then pick **Simulated (no privileges)** in the sidebar and press **Start**.

Leave the Terminal window open while you use it. **Press Ctrl+C, or just close
the window, to stop NetLens** — it shuts the server down cleanly either way,
including if you close the window without pressing anything.

Drag `NetLens.command` to the Dock if you want it one click away. If macOS ever
refuses to open it (only happens to files downloaded from the internet), run
`chmod +x NetLens.command` once, or right-click → Open.

### The same thing from a terminal

```bash
cd ~/Desktop/NetLens
./start.sh --open      # start in the background, open Chrome
./stop.sh              # stop it
```

These assume the environment already exists; `NetLens.command` is the one that
sets it up from nothing.

| command | what it does |
|---|---|
| `./start.sh` | start on port 8501, print the URL |
| `./start.sh --open` | …and open it in Chrome |
| `./start.sh --port 8600` | start on a different port |
| `./start.sh --live` | start under `sudo` so live capture can open raw sockets |
| `./stop.sh` | stop it |
| `./stop.sh --port 8600` | stop an instance on another port |

The dashboard runs in the background, logging to `logs/netlens-<port>.log`,
with its pid in `.netlens-<port>.pid`. Both files are port-scoped so two
instances cannot confuse each other.

The scripts refuse to do anything surprising: `start.sh` will not launch a
second copy over a running one, clears a stale pid file left by a crash, and
reports clearly when the port belongs to some other program instead of
starting anyway. `stop.sh` only kills a process on that port when it is
actually Streamlit running this app — anything else on the port belongs to
someone else and is left alone. A `--live` instance runs as root, so `stop.sh`
re-invokes `sudo` to stop it.

Streamlit can also be run in the foreground if you prefer to watch it:

```bash
.venv/bin/streamlit run app.py
```

For live capture choose **Live interface** in the sidebar; raw sockets need
root (`./start.sh --live`), and Windows needs Npcap.

Other entry points:

```bash
.venv/bin/python selftest.py        # headless proof the pipeline runs, ~35 s
.venv/bin/python evaluate.py        # Phase-5 metrics + end-to-end detection rates
.venv/bin/python validate_parser.py # Phase-2 parser cross-check against tshark
```

---

## Why the model is trained on malicious data

This was the review feedback, and it is the right question. The short answer is
that **anomaly detection and attack classification answer different questions**,
so NetLens does both.

| | asks | needs labels? | can it name the attack? |
|---|---|---|---|
| T2 Isolation Forest | "is this unlike normal *for this network*?" | no | no |
| T3 Random Forest | "which attack is this, and how sure are you?" | **yes** | yes |

An Isolation Forest fitted on the network's own first 60 seconds will tell you
a flow is unusual. It cannot tell you it is a port scan, because nothing ever
showed it one. To put a *name* on an attack the model has to have seen labelled
examples of that attack. So we build them.

**How the labelled data is built** — `netlens/synth.py`

1. Attack scenarios are synthesised as **packet records**, not as feature
   vectors: individual SYNs, RST-ACKs, DNS queries with base32 labels, echo
   requests, each with realistic timing, TTLs and flags.
2. Those records are pushed through the **same `flows.FlowTable`** the live
   dashboard uses. Training features are therefore computed by the identical
   code path as live features — a feature can never mean one thing in training
   and another at runtime.
3. The resulting labelled flows train a Random Forest (`train_model.py`).

Nothing is transmitted on any network. `synth.py` writes Python dicts into
memory; there are no sockets and no raw frames. It is a dataset builder, not an
attack tool.

**Eight classes**, 700 flows each, 5 600 flows total:

`benign` · `port_scan` · `syn_flood` · `dns_tunnel` · `icmp_flood` ·
`ssh_brute_force` · `slowloris` · `data_exfil`

**Results** (held-out 25% split, `data/train_report.txt`):

```
accuracy    0.9914        macro-F1   0.9914        CV macro-F1  0.9933 ± 0.0028
benign / data_exfil / dns_tunnel / icmp_flood / slowloris / ssh_brute_force  →  1.0000 F1
port_scan 0.9665    syn_flood 0.9649
```

The only remaining confusion is `port_scan` ↔ `syn_flood`, and it is an honest
one: both produce 1-3 packet SYN-only flows, and at flow level they genuinely
look alike. They differ in *fan-out*, which is a property of the traffic around
the flow rather than of the flow itself — so the rule tier separates them
(many ports on one host vs many forged sources on one port). That is precisely
why the three tiers run together rather than one replacing the others.

**If your mam wants real captures instead of synthetic ones**, the same
pipeline takes them — no code change:

```bash
.venv/bin/python train_model.py \
  --extra-pcap captures/nmap_lab.pcap:port_scan \
  --extra-pcap captures/browsing.pcap:benign
```

Capture those in an isolated lab VM with `nmap -sS`, `hping3 -S --flood`,
`dig` and `iperf3`, or drop in CIC-IDS2017 PCAPs. `--extra-pcap PATH:LABEL`
folds them in alongside the synthetic flows.

---

## Architecture

```
NIC (promiscuous)
  │
  ├── L1  capture.py   AsyncSniffer on a daemon thread → bounded ring buffer
  │                    (20 000 records, drop-oldest, drop counter)
  ├── L2  parser.py    Ether/IP/TCP/UDP/ICMP/ARP/DNS → packet record dict
  │       flows.py     bidirectional 5-tuple table, idle 15 s / active 120 s
  │                    → 37 features per flow (constant memory per flow)
  ├── L3  detect.py    T1 rules ∥ T2 Isolation Forest ∥ T3 Random Forest
  ├── L4  explain.py   concept registry + TCP session ladder reconstruction
  └── L5  app.py       Streamlit + Plotly, scoped fragment refresh
          engine.py    the producer/consumer seam between capture and UI
```

| module | responsibility | key output |
|---|---|---|
| `netlens/capture.py` | interface enumeration, BPF filter, sniffer thread, ring buffer with drop accounting; live / PCAP / simulated sources behind one interface | raw packet queue |
| `netlens/parser.py` | layer walk, field extraction, port→service mapping, DNS name entropy | packet record dict |
| `netlens/flows.py` | bidirectional flow table, timeout eviction, running statistics | 37-feature vector |
| `netlens/detect.py` | six deterministic detectors + self-baselined Isolation Forest + supervised classifier | scored alerts with evidence |
| `netlens/explain.py` | 27 concept cards, session-ladder builder, plain-language flow reading | explanations |
| `netlens/synth.py` | labelled traffic synthesis, PCAP replay, live simulator | training data |
| `netlens/engine.py` | drains the buffer, advances L2-L4, holds all aggregates | everything the UI renders |
| `app.py` | KPI strip, timeline, protocol mix, top talkers/ports, alert feed, session ladder, model tab, concept library | dashboard |

### The three detector tiers

**T1 — deterministic rules** (`RuleEngine`, 10 s sliding window, no training)

| detector | trigger |
|---|---|
| vertical port scan | ≥ 15 distinct destination ports from one source |
| horizontal sweep | ≥ 10 distinct hosts on one port from one source |
| SYN flood, source side | ≥ 60 SYNs from one source at ≥ 3:1 SYN:SYN-ACK |
| SYN flood, victim side | ≥ 60 SYNs *to one service* at ≥ 3:1, flagged as spoofed when they come from ≥ 10 sources |
| ICMP flood | ≥ 80 echo-requests per window |
| brute force | ≥ 12 new connections to an auth port (22/3389/445/…) |
| DNS tunnel | query label ≥ 3.6 bits/char entropy and ≥ 40 chars |
| ARP spoof | one IP claimed by a second MAC |

The victim-side SYN-flood rule exists because a real flood forges its source
addresses: per-source counting sees four SYNs from each of 200 hosts and never
crosses any threshold. The victim is the only stable identity, which is also
why volumetric alerts de-duplicate on the target rather than the source.

**T2 — Isolation Forest** (label-free, novelty N1)
Fitted on the deployment network's own first 60 s (or 600 flows, whichever
comes first), so "normal" is defined locally and the system works on a network
it has never seen. Alerts below a decision score of −0.05. Each flow gets one
verdict, re-issued only if the flow materially grows.

**T3 — Random Forest** (supervised, needs ≥ 70% confidence to speak)
Names the class and reports the runner-up plus the flow's values for the
model's most important features.

### When a flow is judged

Flow features are only meaningful once a flow has a shape. A session that is
one SYN old has the exact feature vector of a SYN-flood probe, and an SSH
session paused between keystrokes has the exact feature vector of a
brute-force attempt. Both were real false positives during development. So the
flow-scoring tiers wait until a flow is **settled**:

- TCP-terminated (FIN from both sides, or RST) — judged immediately, which is
  what makes scans and brute force fast to catch since their probes get RST; or
- idle longer than 3 s — covers UDP, ICMP and half-open TCP, which never
  announce an ending; or
- ≥ 40 packets — enough shape to judge mid-flight, which catches floods and
  bulk transfers early.

The rule tier works on packet windows rather than flows, so it still carries
the fast path. Answering a second later beats answering confidently and wrong.

---

## Parser validation against tshark (Phase 2)

`parser.py` walks the layers itself, so the only way to know its field
extraction is right is to decode identical bytes with the reference dissector
and compare. `validate_parser.py` does exactly that: every frame is decoded
twice — once by tshark, once by `parse_packet` — and each field is compared
value by value.

```
.venv/bin/python validate_parser.py                      # generated reference capture
.venv/bin/python validate_parser.py --pcap captures/real.pcap
```

It finds tshark inside `/Applications/Wireshark.app` automatically, or takes
`--tshark /path/to/tshark`.

**Result: 100% agreement over 274 field comparisons across 26 frames.**

| compared | fields |
|---|---|
| frame | `frame.len` |
| Ethernet | `eth.src`, `eth.dst` |
| IP / IPv6 | `ip.src`, `ip.dst`, `ip.ttl`, `ipv6.src`, `ipv6.dst`, `ipv6.hlim` |
| TCP | `tcp.srcport`, `tcp.dstport`, `tcp.flags`, `tcp.seq_raw`, `tcp.ack_raw`, `tcp.len`, `tcp.window_size_value` |
| UDP | `udp.srcport`, `udp.dstport`, `udp.length` |
| ICMP | `icmp.type`, `icmpv6.type` |
| ARP | `arp.opcode`, `arp.src.proto_ipv4`, `arp.dst.proto_ipv4` |
| DNS | `dns.qry.name` |

The reference capture is built from the cases that actually break naive
parsers, not happy-path traffic: TCP options (MSS/SACK/timestamps/window
scale) that payload length must not absorb, a bare ACK next to a full-MSS
segment, every flag combination, a non-initial IP fragment carrying no
transport header, a VLAN-tagged frame where the IP layer is not where it
usually sits, IPv6 TCP/UDP/ICMPv6, DNS with both a normal hostname and a
60-char high-entropy label, and TTLs at 1/64/128/255.

Two notes on methodology, both worth being able to defend:

**`tcp.relative_sequence_numbers` is disabled.** Wireshark rewrites sequence
numbers to start at 0 per connection by default, which is friendlier to read
and useless for comparison. The check reads `tcp.seq_raw`/`tcp.ack_raw` with
that preference off, so the comparison is against the bytes on the wire.

**Transport fields are not compared on ICMP frames, and this is deliberate.**
An ICMP error message *quotes* the header of the packet that caused it, so a
destination-unreachable frame contains a second IP header and a second port
pair. tshark reports those quoted values under `tcp.srcport`/`tcp.flags`,
because they are the only TCP fields in the frame. Our parser describes the
outer frame — the thing actually transmitted — and leaves the transport fields
unset. Both are correct; they answer different questions. Those fields are
listed as skipped with that reason rather than quietly counted as passes.

### Three real parser bugs this check found

The run is only worth anything because it failed first — 96.8% on the first
pass, with nine mismatches:

1. **ICMPv6 was not recognised at all.** IPv6 echo requests fell through to a
   generic `"IP"` protocol with no type. Now identified by the IPv6
   next-header value (58) rather than by a Scapy class, since every ICMPv6
   message type is a separate class.
2. **Non-initial IP fragments reported a lowercase protocol name** (`'tcp'`
   instead of `'TCP'`), because Scapy's `i2s` lookup returns lowercase. Every
   downstream protocol comparison is case-sensitive, so this would have
   silently dropped fragments out of the protocol mix.
3. **`payload_len` was 0 where it should have been undefined.** An ARP frame
   and a bare ACK both reported 0, but they mean different things: the ACK
   genuinely carries zero bytes, the ARP frame has no payload concept at all.
   It is now `None` when there is no transport layer, which is also what makes
   the comparison with tshark's absent field meaningful.

The remaining six mismatches were the ICMP-quotation artifact described above
— the parser was right and the comparison was wrong.

---

## Measured results

`evaluate.py` reports two different things, and the second is the honest one.

**A. Classifier metrics** — held-out split of the labelled dataset:
99.14% accuracy, 0.9914 macro-F1, 0.9999 macro ROC-AUC, 100% binary detection
rate with 0 benign flows misclassified as attacks.

**B. End-to-end pipeline detection** — fresh scenarios on an unseen seed
replayed through capture buffer, flow table and all three tiers:

8 independent trials per class, seed 2026:

| attack | detected | first alert | tiers that fired |
|---|---|---|---|
| syn_flood | 8/8 | +0.22 s | rule, model |
| icmp_flood | 8/8 | +0.25 s | rule, baseline, model |
| port_scan | 8/8 | +0.45 s | rule, model |
| dns_tunnel | 8/8 | +0.46 s | rule, model |
| ssh_brute_force | 8/8 | +0.48 s | rule, baseline, model |
| data_exfil | 8/8 | +2.15 s | model |
| slowloris | 8/8 | +137 s | baseline, model |

False positives on benign-only traffic: **zero** from the rule and model tiers;
0.067 alerts per flow from the Isolation Forest, which is calibrated to call
roughly 3% of flows unusual by construction.

The Isolation Forest also flags **95.2% of attack flows** on the labelled set
at a 3.0% benign false-positive rate — without ever having been told what an
attack is. That is the value of keeping tier 2: it covers attacks tier 3 was
never trained on.

Slowloris takes minutes by nature — its packets are 8-25 s apart, so there is
nothing to measure sooner. That is a property of the attack, not a weakness in
the detector, and it is the reason the attack works against volume thresholds.

Capture performance in the simulated harness: ~500 packets/s sustained with
**0 dropped** against a 20 000-record buffer, and 30-45 ms of pipeline
processing per UI refresh.

---

## Mapping to the Review 2 slides

| claim | where it lives |
|---|---|
| N1 self-baselining, label-free detection | `detect.BaselineDetector`, fits on first 60 s of local traffic |
| N2 concept-bound explanation layer | `explain.CONCEPTS` (27 cards), bound to every chart and alert kind |
| N3 live TCP session ladder | `explain.build_ladder` + `app.ladder_figure` |
| N4 decoupled producer-consumer pipeline | `capture.RingBuffer` + `engine.Engine.tick` + `app.pipeline_pump` |
| 20+ flow features | 37, in `flows.FEATURE_NAMES` |
| four deterministic detectors | eight, in `detect.RuleEngine` |
| Isolation Forest on first 60 s | `config.BASELINE_SECONDS` |
| precision/recall per detector | `evaluate.py` section A |
| parser fields cross-checked against tshark | `validate_parser.py` — 100% over 274 comparisons |
| packet drop rate under load | `capture.RingBuffer.dropped`, shown in the KPI strip |
| UI refresh latency | `engine.tick_ms`, shown in the KPI strip |
| flow-table memory footprint | `flows.RunningStat` — constant space per flow |

One deliberate deviation from the slides: the slides describe four
deterministic detectors and a label-free Isolation Forest. The Isolation Forest
is still there and still label-free, but a third supervised tier was added on
review feedback, because label-free novelty detection cannot name an attack.
Both are kept rather than one replacing the other, and the Detection model tab
states exactly which tier produced each alert.

---

## Dashboard tabs

1. **Live dashboard** — KPI strip (packets, volume, flows, alerts, drops,
   buffer, pipeline latency), traffic timeline, protocol mix, top destination
   ports, top talkers, packet-size distribution, each with its concept card.
2. **Alerts** — severity/tier-filtered feed; every alert expands into its
   evidence JSON beside the concept card for the principle it evidences.
3. **Flows & session ladder** — the flow table with verdicts, and the selected
   flow redrawn as a timestamped sequence diagram with its 37-feature vector
   and a plain-language reading of what it did.
4. **Detection model** — live tier status, classifier metrics, per-class
   report, confusion matrix, feature importances.
5. **Concept library** — all 27 cards.

Live panels sit in scoped `st.fragment`s. The pipeline pump is rendered
*outside* the tab set on purpose: Streamlit pauses auto-refresh for fragments
inside an inactive tab, which would stall the pipeline whenever you looked at
another tab. The ring buffer would absorb that without losing packets, but the
dashboard should not lean on it. Flow inspection deliberately does **not**
auto-refresh, so a ladder you are reading does not move.

---

## Layout

```
NetLens/
├── NetLens.command         double-click this: sets up, trains, runs, opens
├── start.sh  stop.sh       run the dashboard in the background
├── app.py                  L5 dashboard
├── train_model.py          trains T3 on labelled attack flows
├── evaluate.py             Phase-5 metrics + end-to-end detection rates
├── selftest.py             headless pipeline smoke test
├── validate_parser.py      Phase-2 cross-check against tshark
├── netlens/
│   ├── config.py           every tunable the report quotes
│   ├── capture.py          L1
│   ├── parser.py           L2a
│   ├── flows.py            L2b  (FEATURE_NAMES lives here)
│   ├── detect.py           L3
│   ├── explain.py          L4
│   ├── synth.py            labelled traffic synthesis + live simulator
│   └── engine.py           orchestration
├── models/netlens_model.joblib
├── data/                   dataset, reports, plots
├── logs/                   dashboard logs (created by start.sh)
└── captures/               reference.pcap, plus any .pcap you want to analyse
```

## Stack

Python 3.12 · Scapy 2.6 (AsyncSniffer over libpcap/BPF) · pandas · NumPy ·
scikit-learn (Isolation Forest + Random Forest) · Streamlit · Plotly ·
matplotlib. Parser cross-checking against `tshark` is automated in
`validate_parser.py`; Wireshark 4.6 is the reference dissector.
