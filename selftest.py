#!/usr/bin/env python3
"""Headless smoke test — proves the whole pipeline runs without the UI.

    python selftest.py            # ~35 s
    python selftest.py --seconds 60

Useful in a review when you want to show the pipeline working without
projecting a browser, and as a quick check after changing any module.
"""

from __future__ import annotations

import argparse
import sys
import time

from netlens.capture import SimulatedSource
from netlens.engine import Engine
from netlens.explain import build_ladder, interpret_flow
from netlens.flows import FEATURE_NAMES


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=35)
    ap.add_argument("--rate", type=float, default=4.0)
    args = ap.parse_args()

    print(f"NetLens self-test — {args.seconds:.0f}s of simulated traffic "
          f"through L1-L4\n")
    src = SimulatedSource(seed=7, benign_rate=args.rate, auto_attacks=True)
    eng = Engine(src)
    eng.start()

    t0, last = time.time(), -1
    while time.time() - t0 < args.seconds:
        eng.tick()
        time.sleep(0.4)
        sec = int(time.time() - t0)
        if sec % 7 == 0 and sec != last:
            last = sec
            k = eng.kpis()
            print(f"  t={sec:3d}s  packets={k['packets']:7,d}  "
                  f"{k['pps_now']:6.0f} pkt/s  flows={k['active_flows']:4d}  "
                  f"alerts={k['alerts']:3d}  dropped={k['dropped']}  "
                  f"tick={k['tick_ms']:5.1f} ms")

    print("\ninjecting one of each attack class...")
    for name in ("port_scan", "syn_flood", "dns_tunnel", "icmp_flood"):
        src.inject(name)
    for _ in range(18):
        eng.tick()
        time.sleep(0.4)

    k = eng.kpis()
    print(f"\nL1 capture     {k['packets']:,} packets, {k['bytes'] / 1e6:.2f} MB, "
          f"{k['dropped']} dropped ({k['drop_rate'] * 100:.3f}%)")
    print(f"L2 flows       {eng.flows.stats()}")
    print(f"L2 features    {len(FEATURE_NAMES)} per flow")
    st = eng.status()
    print(f"L3 tier 1      {st['rules']}")
    print(f"L3 tier 2      {st['baseline']}")
    print(f"L3 tier 3      {st['model']}")
    print(f"L3 alerts      {st['total_alerts']} total, by tier {st['by_tier']}")
    print(f"               by kind {st['by_kind']}")
    print(f"L5 pipeline    {k['tick_ms']:.1f} ms average per refresh")

    print("\nmost recent alerts")
    for a in eng.detector.alerts[:8]:
        print(f"  [{a.severity:8s}] {a.tier:8s} {a.title[:40]:40s} "
              f"{a.source[:21]:21s}"
              + (f" conf={a.confidence:.0%}" if a.confidence else ""))

    flow = max(eng.flows.all_flows(), key=lambda f: f.total_packets, default=None)
    if flow is not None:
        print(f"\nL4 session ladder — {flow.flow_id} "
              f"({flow.proto}, {flow.total_packets} packets)")
        for s in build_ladder(flow)[:6]:
            print(f"  {s['n']:2d} {s['t_ms']:9.2f} ms {s['direction']} "
                  f"{s['label']:9s} {s['bytes']:5d} B  {s['note'][:46]}")
        print("L4 interpretation")
        for line in interpret_flow(flow)["lines"]:
            print(f"  - {line}")

    ok = (k["packets"] > 0 and eng.flows.total_flows_seen > 0
          and st["total_alerts"] > 0)
    print(f"\n{'PASS' if ok else 'FAIL'} — "
          f"capture, flows, detection and explanation all produced output.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
